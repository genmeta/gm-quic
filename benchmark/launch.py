#!/usr/bin/env python3


import os
import subprocess
import re
import json
import sys
import matplotlib.pyplot as plt
import logging
import shutil
import argparse


class ServerRunner:
    name: str
    launch_server: list[str]
    listen_port: int

    def __init__(self, impl_name: str, launch_server: list[str], listen_port: int):
        self.name = impl_name
        self.listen_port = listen_port
        self.launch_server = launch_server

    def run(self) -> subprocess.Popen:
        # 在后台运行server
        return subprocess.Popen(
            self.launch_server,
            cwd=rand_files.path,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={**os.environ, "RUST_LOG": "off"}
        )


class Result:
    success: int
    duration: float
    qps: float

    def __init__(self, success: int, duration: float):
        self.success, self.duration = success, duration
        self.qps = success / duration if duration > 0 else 0

    def __str__(self):
        return f"success={self.success}, duration={self.duration}, qps={self.qps}"

    def __repr__(self):
        return self.__str__()

    @staticmethod
    def average(results: list['Result']) -> 'Result':
        total_success, total_duration = 0, 0
        total_success = sum(result.success for result in results)
        total_duration = sum(result.duration for result in results)
        return Result(total_success, total_duration)


root = os.path.join(os.path.dirname(__file__))


class RandomFiles:
    path = os.path.join(root, "rand_files")

    def __init__(self):
        if not os.path.exists(self.path):
            os.makedirs(self.path)

    def gen(self, file_size: int) -> str:
        file_name = f"rand_file_{file_size}.bin"
        logging.info(f"Generating {file_name}...")
        file_path = os.path.join(self.path, file_name)
        if not os.path.exists(file_path):
            with open(file_path, "wb") as f:
                f.write(os.urandom(int(file_size) * 1024))
        return file_name


class Certs:
    path = os.path.join(root, "certs")

    root_cert = os.path.join(path, "root_cert.pem")
    root_key = os.path.join(path, "root_key.pem")
    server_cert = os.path.join(path, "server_cert.pem")
    server_key = os.path.join(path, "server_key.pem")
    server_csr = os.path.join(path, "server_csr.pem")
    server_cert_der = os.path.join(path, "server_cert.der")
    server_key_der = os.path.join(path, "server_key.der")

    def __init__(self):
        pass

    def gen(self):
        if not os.path.exists(self.path):
            logging.info("Generating certs...")
            os.makedirs(self.path)

            # CA
            subprocess.run(
                ["openssl", "ecparam", "-name", "prime256v1",
                    "-genkey", "-out", self.root_key])
            subprocess.run(
                ["openssl", "req", "-new", "-x509", "-key", self.root_key, "-out", self.root_cert,
                 "-days", "3650", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"])
            # Server
            subprocess.run(
                ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-out", self.server_key])
            subprocess.run(
                ["openssl", "req", "-new", "-key", self.server_key, "-out",
                 self.server_csr,  "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"])
            subprocess.run(
                ["openssl", "x509", "-req", "-in", self.server_csr, "-CA", self.root_cert,
                 "-CAkey", self.root_key, "-CAcreateserial", "-out", self.server_cert,
                 "-days", "365", "-copy_extensions", "copy"])
            # Convert pem to der
            subprocess.run(
                ["openssl", "x509", "-in", self.server_cert, "-outform", "der",
                 "-out", self.server_cert_der])
            subprocess.run(
                ["openssl", "ec", "-in", self.server_key, "-outform", "der",
                 "-out", self.server_key_der])


rand_files = RandomFiles()
ecc_certs = Certs()

go_quic_dir = os.path.join(root, "go-quic-demo")
gm_quic_dir = os.path.join(root, "..")
tquic_dir = os.path.join(root, "tquic")
quinn_dir = os.path.join(root, "h3")
quiche_dir = os.path.join(root, "quiche")


def git_clone(owner: str, repo: str, branch: str) -> None:
    if not os.path.exists(os.path.join(root, repo)):
        logging.info(f"Cloning {owner}/{repo}...")
        subprocess.run(
            ["git", "clone", "--recursive", "--branch", branch,
             f"https://github.com/{owner}/{repo}"],
            cwd=root
        )


def go_quic_runner() -> ServerRunner:
    logging.info("Building go-quic server...")

    git_clone("eareimu", "go-quic-demo", "main")

    # 编译
    subprocess.run(
        ["go", "get", "example/quic-server",],
        cwd=go_quic_dir
    )
    subprocess.run(
        ["go", "build", "-ldflags=-s -w", "-trimpath", "-o", "quic_server"],
        cwd=go_quic_dir
    )

    binary = os.path.join(go_quic_dir, "quic_server")
    launch = [
        binary,
        "-c", ecc_certs.server_cert,
        "-k", ecc_certs.server_key,
        "-a", "[::1]:4430",
    ]

    return ServerRunner('go-quic', launch, 4430)


def gm_quic_runner() -> ServerRunner:
    logging.info("Building gm-quic server...")

    # git_clone("genmeta", "gm-quic", "main")

    # 编译
    subprocess.run(
        ["cargo", "build", "--release", "--package",
            "h3-shim", "--example", "h3-server"],
        cwd=gm_quic_dir
    )

    launch = [
        os.path.join(gm_quic_dir,
                     "target", "release", "examples", "h3-server"),
        "-c", ecc_certs.server_cert,
        "-k", ecc_certs.server_key,
        "-l", "[::1]:4431"
    ]

    return ServerRunner('gm-quic', launch, 4431)


def tquic_runner() -> ServerRunner:
    logging.info("Building tquic server...")

    git_clone("Tencent", "tquic", "v1.6.0")

    subprocess.run(
        ["cargo", "build", "--release", "--package",
            "tquic_tools", "--bin", "tquic_server"],
        cwd=tquic_dir
    )

    launch = [
        os.path.join(tquic_dir, "target", "release", "tquic_server"),
        "-c", ecc_certs.server_cert,
        "-k", ecc_certs.server_key,
        "-l", "[::1]:4432",
        "--log-level", "OFF",
    ]

    return ServerRunner('tquic', launch, 4432)


def quinn_runner() -> ServerRunner:
    logging.info("Building quinn server...")

    git_clone("hyperium", "h3", "h3-quinn-v0.0.9")

    subprocess.run(
        ["cargo", "build", "--release", "--example", "server"],
        cwd=quinn_dir
    )

    launch = [
        os.path.join(quinn_dir,
                     "target", "release", "examples", "server"),
        "-c", ecc_certs.server_cert_der,
        "-k", ecc_certs.server_key_der,
        "-l", "[::1]:4433",
        "-d", "."  # 实际上是rand-files
    ]

    return ServerRunner('quinn', launch, 4433)


def cf_quiche_runner() -> ServerRunner:
    logging.info("Building cloudflare-quiche server...")

    git_clone("cloudflare", "quiche", "0.23.4")

    subprocess.run(
        ["cargo", "build", "--release", "--bin", "quiche-server"],
        cwd=quiche_dir
    )

    launch = [
        os.path.join(quiche_dir,
                     "target", "release", "quiche-server"),
        "--key", ecc_certs.server_key,
        "--cert", ecc_certs.server_cert,
        "--listen", "[::1]:4434",
        "--root", ".",
        "--no-retry"
    ]

    return ServerRunner('cloudflare quiche', launch, 4434)


class H3Client:
    stress: int
    requests: int
    progress: bool

    def __init__(self, stress: int = 1024*30, requests: int = 8, progress: bool = False):
        self.stress = stress
        self.requests = requests
        self.progress = progress

    def run_once(self, server_runner: ServerRunner, file_size: int, seq: int = 0) -> Result:
        # 在后台启动server
        server = server_runner.run()

        launch_client = [
            "cargo", "run", "--package", "h3-shim",
            "--release", "--example", "h3-stress-client", "--",
                         "--conns", str(int(self.stress / file_size)),
                         "--reqs", str(self.requests),
                         "--roots", ecc_certs.root_cert,
                         "--progress", "summary" if self.progress else "none",
                         f'https://localhost:{server_runner.listen_port}/{rand_files.gen(file_size)}'
        ]

        log_dir = os.path.join(output_dir, "client_log")
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        f = open(
            os.path.join(log_dir, f"{server_runner.name}_{file_size}KB_{seq}.log"), "w+")

        try:
            cr = subprocess.run(
                launch_client,
                cwd=gm_quic_dir,
                env={**os.environ, "RUST_LOG": "counting"},
                stdout=f,
                text=True,
                timeout=15
            )
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()
            logging.warning(
                f"Timeout expired for running {server_runner.name} {file_size}KB")
            f.close()
            return Result(success=0, duration=0)

        server.kill()
        server.wait()
        f.seek(0)
        output = f.read()
        f.close()

        # Extract total_time and success_queries using regex
        match = re.search(
            r"success_queries=(\d+).*?total_time=(\d+\.?\d*)", output)
        if match:
            success_queries = int(match.group(1))
            total_time = float(match.group(2))
            return Result(success=int(success_queries), duration=total_time)
        else:
            logging.error(f"Failed to parse benchmark output: {output}")
            return Result(success=0, duration=0)

    def run_many(self, server_runner: ServerRunner, file_size: int, times: int = 3) -> list[Result]:
        results = []
        for seq in range(0, times):
            once = self.run_once(server_runner, file_size, seq)
            logging.info(
                f"Run {server_runner.name} {file_size}KB complete: {once}")
            results.append(once)
        return results


def run() -> dict[dict[str, list[Result]]]:
    ecc_certs.gen()
    runners = [
        go_quic_runner(),
        gm_quic_runner(),
        tquic_runner(),
        quinn_runner(),
        cf_quiche_runner()
    ]

    client = H3Client(stress=2048*15, requests=8, progress=True)

    results = {}

    return {
        runner.name: {
            file_size: client.run_many(runner, file_size, times=10)
            for file_size in [15, 30, 2048]
        }
        for runner in runners
    }


output_dir = os.path.join(root, "output")


def plot_results(results: dict[str, dict[str, list[Result]]]):
    # [实现名, [文件大小, 多次运行的结果]]
    plot_out_dir = os.path.join(output_dir, "plots")
    if not os.path.exists(plot_out_dir):
        os.makedirs(plot_out_dir)

    implementations = list(results.keys())
    file_sizes = results[implementations[0]].keys()

    for file_size in file_sizes:
        plt.figure(figsize=(10, 6))
        # 平均图
        qps_values = [
            Result.average(results[impl][file_size]).qps
            for impl in implementations
        ]
        bars = plt.bar(implementations, qps_values)

        plt.title(f"file size {file_size}KB")
        plt.xlabel("Implementations")
        plt.ylabel("QPS")
        plt.xticks(rotation=45)

        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2, height,
                     round(height, 2), ha='center', va='bottom')

        plt.tight_layout()
        plt.savefig(os.path.join(plot_out_dir, f"benchmark_{file_size}KB.png"))
        plt.close()

        # 每个实现的多次运行结果图
        for impl in implementations:
            plt.figure(figsize=(10, 6))
            qps_values = [result.qps for result in results[impl][file_size]]
            bars = plt.bar([i for i in range(len(qps_values))], qps_values)

            plt.title(f"{impl} file size {file_size}KB")
            plt.xlabel("Runs")
            plt.ylabel("QPS")
            plt.xticks(rotation=45)

            for bar in bars:
                height = bar.get_height()
                plt.text(bar.get_x() + bar.get_width()/2, height,
                         round(height, 2), ha='center', va='bottom')

            plt.tight_layout()
            plt.savefig(
                os.path.join(plot_out_dir, f"{impl}_{file_size}KB.png"))
            plt.close()


def save_results(results: dict[str, dict[str, list[Result]]]):
    """save results to json file"""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    with open(os.path.join(output_dir, "results.json"), "w") as f:
        json.dump({
            impl: {
                size: [r.__dict__ for r in results_list]
                for size, results_list in sizes_results.items()
            }
            for impl, sizes_results in results.items()
        }, f, indent=2)


def load_results(path: str = os.path.join(output_dir, "results.json")) -> dict[str, dict[str, list[Result]]]:
    """load results from json file"""
    with open(path, "r") as f:
        return {
            impl: {
                size: [Result(r["success"], r["duration"]) for r in runs]
                for size, runs in sizes_results.items()
            }
            for impl, sizes_results in json.load(f).items()
        }


if __name__ == "__main__":
    logging.root.setLevel(logging.INFO)

    parser = argparse.ArgumentParser(
        description='QUIC implementation benchmark')
    subparsers = parser.add_subparsers(dest='command', required=True)

    # Run command
    run_parser = subparsers.add_parser(
        'run', help='Run benchmark and save results')

    # Load command
    load_parser = subparsers.add_parser(
        'load', help='Load and plot results from file')
    load_parser.add_argument('file', nargs='?', default=os.path.join(output_dir, "results.json"),
                             help='Results JSON file path')

    # Clean command
    clean_parser = subparsers.add_parser('clean', help='Clean generated files')
    clean_parser.add_argument('--all', action='store_true',
                              help='Also remove git cloned implementations')

    args = parser.parse_args()

    if args.command == 'run':
        results = run()
        save_results(results)
    elif args.command == 'load':
        results = load_results(args.file)
    elif args.command == 'clean':
        paths = [rand_files.path, ecc_certs.path]
        if args.all:
            paths.extend([go_quic_dir, tquic_dir, quinn_dir, quiche_dir])
        for path in paths:
            if os.path.exists(path):
                shutil.rmtree(path)
        exit(0)

    plot_results(results)

    print(results)
