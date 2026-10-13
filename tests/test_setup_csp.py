"""Real cross-origin form redirects; a deny-only proxy prevents provider I/O.

Run browser cases with test-only playwright and TEST_CHROMIUM. Unlike a local
redirect stub, these cases exercise Chromium's CSP checks on redirect targets.
"""
import os
import tempfile
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock

from cortex_broker.setup import make_server

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None


class SetupCSPTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.server = make_server(self.tmp.name, 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.connects = []
        connects = self.connects

        class DenyProxy(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_CONNECT(self):
                connects.append(self.path)
                self.send_error(502, 'External traffic denied by test')

            def do_GET(self):
                self.send_error(502, 'External traffic denied by test')

        self.proxy = ThreadingHTTPServer(('127.0.0.1', 0), DenyProxy)
        self.proxy.daemon_threads = True
        self.proxy_thread = threading.Thread(target=self.proxy.serve_forever, daemon=True)
        self.proxy_thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.proxy.shutdown()
        self.proxy.server_close()
        self.proxy_thread.join()
        self.tmp.cleanup()

    def test_setup_csp_exact_authorization_origin(self):
        http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with http.open(self.server.origin + '/') as response:
            self.assertEqual(
                "default-src 'none'; form-action 'self' https://auth.openai.com; "
                "frame-ancestors 'none'; base-uri 'none'",
                response.headers['Content-Security-Policy'])

    def browser_redirect(self, unrelated=False):
        if unrelated:
            self.server.auth.begin = Mock(return_value='https://untrusted.example/blocked')
        else:
            # Preserve actual authorization URL generation and isolated pending state.
            self.server.auth.begin = Mock(wraps=self.server.auth.begin)
        errors = []
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                executable_path=os.environ['TEST_CHROMIUM'], headless=True,
                proxy={'server': f'http://127.0.0.1:{self.proxy.server_port}',
                       'bypass': '127.0.0.1'})
            try:
                context = browser.new_context(service_workers='block')
                page = context.new_page()
                page.on('console', lambda msg: errors.append(msg.text)
                        if msg.type == 'error' else None)
                page.goto(self.server.origin + '/')
                if unrelated:
                    with page.expect_event('console', timeout=5000,
                                           predicate=lambda msg: 'form-action' in msg.text):
                        page.get_by_role('button', name='Continue with ChatGPT', exact=True).click(no_wait_after=True)
                    self.assertEqual(self.server.origin + '/', page.url)
                    self.assertFalse(any('untrusted.example' in c for c in self.connects))
                else:
                    # A proxy refusal proves CSP admitted the real redirect; it
                    # does NOT prove provider sign-in. No CONNECT is forwarded.
                    with page.expect_event('requestfailed', timeout=5000,
                                           predicate=lambda req: req.url.startswith(
                                               'https://auth.openai.com/api/accounts/authorize?')):
                        page.get_by_role('button', name='Continue with ChatGPT', exact=True).click(no_wait_after=True)
                    self.assertIn('auth.openai.com:443', self.connects)
                    self.assertFalse(any('form-action' in e for e in errors))
                self.server.auth.begin.assert_called_once_with(None)
            finally:
                browser.close()

    @unittest.skipUnless(sync_playwright and os.environ.get('TEST_CHROMIUM'),
                         'requires test-only playwright and TEST_CHROMIUM')
    def test_browser_allows_real_authorization_redirect(self):
        self.browser_redirect()

    @unittest.skipUnless(sync_playwright and os.environ.get('TEST_CHROMIUM'),
                         'requires test-only playwright and TEST_CHROMIUM')
    def test_browser_blocks_unrelated_redirect(self):
        self.browser_redirect(unrelated=True)


if __name__ == '__main__':
    unittest.main()
