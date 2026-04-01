module.exports = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'header-max-length': [2, 'always', 160],
    'body-max-line-length': [2, 'always', 160],
    'footer-max-line-length': [2, 'always', 160],
  },
}
