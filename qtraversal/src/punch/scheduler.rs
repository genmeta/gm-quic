use std::{
    collections::{HashMap, VecDeque},
    io,
    net::SocketAddr,
    sync::{Arc, LazyLock, Mutex},
    task::{Context, Poll, Waker},
    time::Duration,
};

use qbase::net::{AddrFamily, Family};
use tokio::time::Instant;

pub static SCHEDULER: LazyLock<Arc<Mutex<Scheduler>>> =
    LazyLock::new(|| Arc::new(Mutex::new(Scheduler::new())));

const MAX_SOCKET_COUNT_PER_INTERFACE: u32 = 300;
const MAX_EXTERNAL_PORTS_PER_INTERFACE: u32 = 300;
const MAX_TOTAL_SOCKET_COUNT: u32 = 600;
const MAX_TOTAL_EXTERNAL_PORTS: u32 = 1200;
const RELEASE_PORT_INTERVAL: Duration = Duration::from_secs(60);

pub struct Scheduler {
    interfaces: HashMap<InterfaceKey, InterfaceScheduler>,
    // 全局统计
    pub(crate) total_allocated_socket: u32,
    pub(crate) total_allocated_ports: u32,
    total_cooling_ports: VecDeque<(Instant, u32)>,
}

impl Scheduler {
    fn new() -> Self {
        Self {
            interfaces: HashMap::new(),
            total_allocated_socket: 0,
            total_allocated_ports: 0,
            total_cooling_ports: VecDeque::new(),
        }
    }

    fn clean_expired_global_ports(&mut self) {
        let now = Instant::now();
        self.total_cooling_ports.retain(|(time, count)| {
            if now - *time > RELEASE_PORT_INTERVAL {
                self.total_allocated_ports = self.total_allocated_ports.saturating_sub(*count);
                false
            } else {
                true
            }
        });
    }

    fn global_available_port(&self) -> u32 {
        let sockets_avail = MAX_TOTAL_SOCKET_COUNT.saturating_sub(self.total_allocated_socket);
        let ports_avail = MAX_TOTAL_EXTERNAL_PORTS.saturating_sub(self.total_allocated_ports);
        sockets_avail.min(ports_avail)
    }

    pub fn poll_port_allocation(
        &mut self,
        cx: &Context,
        dest: SocketAddr,
        interface: String,
        expect: u32,
    ) -> Poll<io::Result<u32>> {
        // 清理过期的全局冷却端口
        self.clean_expired_global_ports();

        let family = dest.ip().family();
        let key = InterfaceKey::new(interface.clone(), family);

        // 检查全局限制
        let global_available = self.global_available_port();

        let scheduler = self
            .interfaces
            .entry(key.clone())
            .or_insert_with(InterfaceScheduler::new);
        let interface_available = scheduler.available_port();
        let actual_available = global_available.min(interface_available).min(expect);

        tracing::trace!(target: "punch",
            global_available, interface_available, actual_available, expect,
            total_socket = self.total_allocated_socket, total_ports = self.total_allocated_ports,
            "Try alloc port with global limits"
        );

        if actual_available >= expect {
            match scheduler.poll_port_allocation(cx, dest, expect) {
                Poll::Ready(Ok(allocated)) => {
                    self.total_allocated_socket += allocated;
                    self.total_allocated_ports += allocated;
                    tracing::trace!(target: "punch", ?dest, interface, allocated, "Port allocation success");
                    Poll::Ready(Ok(allocated))
                }
                Poll::Pending => {
                    tracing::trace!(target: "punch", ?dest, interface, expected = expect, "Port allocation pending after interface check");
                    Poll::Pending
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            }
        } else if actual_available > 0 {
            match scheduler.poll_port_allocation(cx, dest, actual_available) {
                Poll::Ready(Ok(allocated)) => {
                    self.total_allocated_socket += allocated;
                    self.total_allocated_ports += allocated;
                    tracing::trace!(target: "punch", ?dest, interface, allocated, expected = expect, "Port partial allocation");
                    Poll::Ready(Ok(allocated))
                }
                Poll::Pending => {
                    tracing::trace!(target: "punch", ?dest, interface, expected = actual_available, "Port partial allocation pending");
                    Poll::Pending
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            }
        } else {
            scheduler.waiting.push_back((dest, cx.waker().clone()));
            tracing::trace!(target: "punch", ?dest, interface, expected = expect, "Port allocation pending");
            Poll::Pending
        }
    }

    pub fn release_port(
        &mut self,
        count: u32,
        dst: SocketAddr,
        interface: String,
    ) -> io::Result<()> {
        let family = dst.ip().family();
        let key = InterfaceKey::new(interface.clone(), family);

        if let Some(scheduler) = self.interfaces.get_mut(&key) {
            let result = scheduler.release_port(count, dst);

            if result.is_ok() {
                // 更新全局统计
                self.total_allocated_socket = self.total_allocated_socket.saturating_sub(count);
                let now = Instant::now();
                self.total_cooling_ports.push_back((now, count));

                tracing::trace!(target: "punch", ?dst, interface, released = count, "Port release success");

                // 唤醒等待的任务
                for (_, scheduler) in self.interfaces.iter_mut() {
                    if let Some(waker) = scheduler.waiting.pop_front().map(|(_, waker)| waker) {
                        waker.wake();
                    }
                }
            }

            result
        } else {
            tracing::trace!(target: "punch", ?dst, interface_name = key.interface_name, "Interface scheduler not found");
            Err(io::Error::other("Interface scheduler not found"))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InterfaceKey {
    interface_name: String,
    family: Family,
}

impl InterfaceKey {
    pub fn new(interface_name: String, family: Family) -> Self {
        Self {
            interface_name,
            family,
        }
    }
}

struct InterfaceScheduler {
    allocated_socket: u32,
    allocated_ports: u32,
    cooling_ports: VecDeque<(Instant, u32)>,
    port_map: HashMap<SocketAddr, u32>,
    waiting: VecDeque<(SocketAddr, Waker)>,
}

impl InterfaceScheduler {
    fn new() -> Self {
        Self {
            allocated_socket: 0,
            allocated_ports: 0,
            cooling_ports: VecDeque::new(),
            port_map: HashMap::new(),
            waiting: VecDeque::new(),
        }
    }

    fn poll_port_allocation(
        &mut self,
        cx: &Context,
        dest: SocketAddr,
        expect: u32,
    ) -> Poll<io::Result<u32>> {
        self.clean_expired_ports();
        let available = self.available_port().min(expect);
        tracing::trace!(target: "punch", available, expect, "Try alloc port");

        if available >= expect {
            self.allocate_port(dest, expect);
            self.remove_waker(dest);
            tracing::trace!(target: "punch", ?dest, allocated = expect, "Interface port allocation success");
            Poll::Ready(Ok(expect))
        } else {
            self.waiting.push_back((dest, cx.waker().clone()));
            tracing::trace!(target: "punch", ?dest, expected = expect, available, "Interface port allocation pending");
            Poll::Pending
        }
    }

    #[inline]
    fn clean_expired_ports(&mut self) {
        let now = Instant::now();
        self.cooling_ports.retain(|(time, count)| {
            if now - *time > RELEASE_PORT_INTERVAL {
                self.allocated_ports = self.allocated_ports.saturating_sub(*count);
                false
            } else {
                true
            }
        });
    }

    #[inline]
    fn available_port(&self) -> u32 {
        let sockets_avail = MAX_SOCKET_COUNT_PER_INTERFACE.saturating_sub(self.allocated_socket);
        let ports_avail = MAX_EXTERNAL_PORTS_PER_INTERFACE.saturating_sub(self.allocated_ports);
        sockets_avail.min(ports_avail)
    }

    #[inline]
    fn allocate_port(&mut self, dest: SocketAddr, count: u32) {
        self.allocated_socket += count;
        self.allocated_ports += count;
        self.port_map
            .get_mut(&dest)
            .map(|v| *v += count)
            .unwrap_or_else(|| {
                self.port_map.insert(dest, count);
            });
    }

    fn remove_waker(&mut self, dest: SocketAddr) {
        if let Some(pos) = self.waiting.iter().position(|(addr, _)| addr == &dest) {
            self.waiting.remove(pos);
        }
    }

    fn release_port(&mut self, count: u32, dst: SocketAddr) -> io::Result<()> {
        if self.allocated_socket < count {
            tracing::trace!(
                target: "punch", allocated_ports=self.allocated_ports, count, ?dst,
                "Socket count is not enough",
            );
            return Err(io::Error::other("socket count is not enough"));
        }
        let allocated_count = self.port_map.get(&dst).copied().unwrap_or(0);
        if allocated_count < count {
            tracing::trace!(target: "punch", ?dst, allocated_count, count, "Socket count mismatch");
            return Err(io::Error::other("socket count mismatch"));
        }
        tracing::trace!(target: "punch", count, self.allocated_socket, self.allocated_ports, "Schedule release port");
        self.allocated_socket -= count;
        let now = Instant::now();
        self.cooling_ports.push_back((now, count));
        if allocated_count > count {
            self.port_map.insert(dst, allocated_count - count);
        } else {
            self.port_map.remove(&dst);
        }
        self.waiting.retain(|(addr, _waker)| addr != &dst);
        tracing::trace!(target: "punch", ?dst, released = count, "Interface port release success");
        if let Some(waker) = self.waiting.pop_front().map(|(_, waker)| waker) {
            waker.wake();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use futures::task::noop_waker_ref;

    use super::*;

    fn create_test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)
    }

    fn create_context() -> Context<'static> {
        let waker = noop_waker_ref();
        Context::from_waker(waker)
    }

    #[test]
    fn test_scheduler_new() {
        let scheduler = Scheduler::new();
        assert_eq!(scheduler.total_allocated_socket, 0);
        assert_eq!(scheduler.total_allocated_ports, 0);
        assert!(scheduler.interfaces.is_empty());
        assert!(scheduler.total_cooling_ports.is_empty());
    }

    #[test]
    fn test_poll_port_allocation_success() {
        let mut scheduler = Scheduler::new();
        let cx = create_context();
        let dest = create_test_addr();
        let interface_name = "eth0".to_string();
        let expect = 10;

        let result = scheduler.poll_port_allocation(&cx, dest, interface_name.clone(), expect);
        assert!(matches!(result, Poll::Ready(Ok(count)) if count == expect));

        // 检查全局统计
        assert_eq!(scheduler.total_allocated_socket, expect);
        assert_eq!(scheduler.total_allocated_ports, expect);

        // 检查接口统计
        let key = InterfaceKey::new(interface_name, dest.ip().family());
        let interface_scheduler = scheduler.interfaces.get(&key).unwrap();
        assert_eq!(interface_scheduler.allocated_socket, expect);
        assert_eq!(interface_scheduler.allocated_ports, expect);
        assert_eq!(*interface_scheduler.port_map.get(&dest).unwrap(), expect);
    }

    #[test]
    fn test_poll_port_allocation_pending() {
        let mut scheduler = Scheduler::new();
        let cx = create_context();
        let dest = create_test_addr();
        let interface_name = "eth0".to_string();

        // 先分配所有全局端口
        let _ = scheduler.poll_port_allocation(
            &cx,
            dest,
            interface_name.clone(),
            MAX_TOTAL_SOCKET_COUNT,
        );

        // 现在再次分配应该 Pending
        let expect = 1;
        let result = scheduler.poll_port_allocation(&cx, dest, interface_name.clone(), expect);
        assert!(matches!(result, Poll::Pending));

        // 检查等待队列
        let key = InterfaceKey::new(interface_name, dest.ip().family());
        let interface_scheduler = scheduler.interfaces.get(&key).unwrap();
        assert_eq!(interface_scheduler.waiting.len(), 1);
    }

    #[test]
    fn test_release_port() {
        let mut scheduler = Scheduler::new();
        let cx = create_context();
        let dest = create_test_addr();
        let interface_name = "eth0".to_string();
        let count = 10;

        // 先分配
        let result = scheduler.poll_port_allocation(&cx, dest, interface_name.clone(), count);
        assert!(matches!(result, Poll::Ready(Ok(c)) if c == count));

        // 释放
        let release_result = scheduler.release_port(count, dest, interface_name.clone());
        assert!(release_result.is_ok());

        // 检查全局统计（冷却中）
        assert_eq!(scheduler.total_allocated_socket, 0);
        assert_eq!(scheduler.total_cooling_ports.len(), 1);

        // 检查接口统计
        let key = InterfaceKey::new(interface_name, dest.ip().family());
        let interface_scheduler = scheduler.interfaces.get(&key).unwrap();
        assert_eq!(interface_scheduler.allocated_socket, 0);
        assert!(!interface_scheduler.port_map.contains_key(&dest));
    }

    #[test]
    fn test_global_limits() {
        let mut scheduler = Scheduler::new();
        let cx = create_context();
        let dest = create_test_addr();
        let interface_name1 = "eth0".to_string();
        let interface_name2 = "eth1".to_string();

        // 在第一个接口分配到接口限制
        let expect = MAX_SOCKET_COUNT_PER_INTERFACE; // 300
        let result = scheduler.poll_port_allocation(&cx, dest, interface_name1.clone(), expect);
        assert!(matches!(result, Poll::Ready(Ok(c)) if c == expect));
        assert_eq!(scheduler.total_allocated_socket, expect);

        // 在第二个接口分配剩余的全局限制
        let expect2 = MAX_TOTAL_SOCKET_COUNT - MAX_SOCKET_COUNT_PER_INTERFACE; // 600 - 300 = 300
        let result2 = scheduler.poll_port_allocation(&cx, dest, interface_name2.clone(), expect2);
        assert!(matches!(result2, Poll::Ready(Ok(c)) if c == expect2));
        assert_eq!(scheduler.total_allocated_socket, MAX_TOTAL_SOCKET_COUNT);

        // 再次分配应该 Pending
        let result3 = scheduler.poll_port_allocation(&cx, dest, interface_name1, 1);
        assert!(matches!(result3, Poll::Pending));
    }

    #[test]
    fn test_interface_limits() {
        let mut scheduler = Scheduler::new();
        let cx = create_context();
        let dest = create_test_addr();
        let interface_name = "eth0".to_string();

        // 分配到接口限制
        let expect = MAX_SOCKET_COUNT_PER_INTERFACE;
        let result = scheduler.poll_port_allocation(&cx, dest, interface_name.clone(), expect);
        assert!(matches!(result, Poll::Ready(Ok(c)) if c == expect));

        let key = InterfaceKey::new(interface_name.clone(), dest.ip().family());
        let interface_scheduler = scheduler.interfaces.get(&key).unwrap();
        assert_eq!(interface_scheduler.allocated_socket, expect);

        // 再次分配应该 Pending
        let result2 = scheduler.poll_port_allocation(&cx, dest, interface_name, expect);
        assert!(matches!(result2, Poll::Pending));
    }

    #[test]
    fn test_global_stats_not_updated_on_interface_pending() {
        let mut scheduler = Scheduler::new();
        let cx = create_context();
        let dest = create_test_addr();
        let interface_name = "eth0".to_string();

        // 先分配一些端口，让接口可用端口减少
        let _ = scheduler.poll_port_allocation(&cx, dest, interface_name.clone(), 10);

        // 现在接口调度器的状态：allocated_socket = 10, available = 290
        // 全局可用 = 600 - 10 = 590

        // 模拟接口调度器内部状态变化，让它认为没有可用端口
        // 我们通过直接修改接口调度器的 allocated_socket 来模拟
        let key = InterfaceKey::new(interface_name.clone(), dest.ip().family());
        if let Some(interface_scheduler) = scheduler.interfaces.get_mut(&key) {
            // 让接口认为已经分配了所有端口
            interface_scheduler.allocated_socket = MAX_SOCKET_COUNT_PER_INTERFACE;
            interface_scheduler.allocated_ports = MAX_EXTERNAL_PORTS_PER_INTERFACE;
        }

        // 现在全局调度器认为全局可用 590，接口可用 0，actual_available = 0
        // 所以应该直接返回 Pending，不更新全局统计
        let result = scheduler.poll_port_allocation(&cx, dest, interface_name.clone(), 1);
        assert!(matches!(result, Poll::Pending));

        // 全局统计应该没有变化（仍然是 10）
        assert_eq!(scheduler.total_allocated_socket, 10);
        assert_eq!(scheduler.total_allocated_ports, 10);
    }

    #[test]
    fn test_mutex_protection() {
        use std::sync::Arc;

        use tokio::sync::Mutex;

        // 创建一个独立的调度器用于测试
        let scheduler = Arc::new(Mutex::new(Scheduler::new()));

        // 模拟多个线程同时访问
        let mut handles = vec![];

        for _ in 0..5 {
            let scheduler_clone = Arc::clone(&scheduler);
            let handle = std::thread::spawn(move || {
                // 阻塞等待锁
                let mut scheduler = scheduler_clone.blocking_lock();

                // 简单的状态检查
                let initial_socket = scheduler.total_allocated_socket;

                // 确保在锁保护下访问是安全的
                assert_eq!(scheduler.total_allocated_socket, initial_socket);

                // 模拟一些操作
                scheduler.total_allocated_socket += 1;
                scheduler.total_allocated_ports += 1;

                true
            });
            handles.push(handle);
        }

        // 等待所有线程完成
        for handle in handles {
            assert!(handle.join().unwrap());
        }

        // 检查最终状态 - 应该有 5 次增加
        let scheduler = scheduler.try_lock().unwrap();
        assert_eq!(scheduler.total_allocated_socket, 5);
        assert_eq!(scheduler.total_allocated_ports, 5);
    }
}
