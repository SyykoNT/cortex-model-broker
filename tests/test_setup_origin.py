"""Origin regressions, including an optional real Chromium form submission.

Browser coverage: install playwright as a test-only dependency and set
TEST_CHROMIUM to a Chromium executable. No provider requests are made.
"""
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from unittest.mock import Mock

from cortex_broker.setup import make_server

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None


class SetupOriginTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.server = make_server(self.tmp.name, 0)
        self.server.auth.begin = Mock(return_value=self.server.origin + '/connected')
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.tmp.cleanup()

    def test_setup_referrer_policy_same_origin(self):
        with self.http.open(self.server.origin + '/') as response:
            self.assertEqual(200, response.status)
            self.assertEqual('same-origin', response.headers['Referrer-Policy'])

    def test_null_origin_refused_with_valid_csrf(self):
        body = urllib.parse.urlencode({'csrf': self.server.csrf, 'account': ''}).encode()
        request = urllib.request.Request(
            self.server.origin + '/auth/start', data=body,
            headers={'Origin': 'null', 'Content-Type': 'application/x-www-form-urlencoded'})
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.http.open(request)
        with error.exception as response:
            self.assertEqual(403, response.code)
            self.assertEqual(b'Invalid origin', response.read())
        self.server.auth.begin.assert_not_called()

    @unittest.skipUnless(sync_playwright and os.environ.get('TEST_CHROMIUM'),
                         'requires test-only playwright and TEST_CHROMIUM')
    def test_browser_submits_real_form_with_same_origin(self):
        # Keep the actual page, form, CSRF and request guards. Stub only the
        # provider authorization destination and deny all off-origin traffic.
        blocked = []
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                executable_path=os.environ['TEST_CHROMIUM'], headless=True)
            try:
                context = browser.new_context(service_workers='block')

                def local_only(route):
                    if route.request.url.startswith(self.server.origin + '/'):
                        route.continue_()
                    else:
                        blocked.append(route.request.url)
                        route.abort()

                context.route('**/*', local_only)
                page = context.new_page()
                page.goto(self.server.origin + '/')
                with page.expect_response(lambda r: r.url == self.server.origin + '/auth/start') as result:
                    page.get_by_role('button', name='Continue with ChatGPT', exact=True).click()
                response = result.value
                self.assertEqual(303, response.status)
                self.assertEqual(self.server.origin, response.request.all_headers()['origin'])
                page.wait_for_url(self.server.origin + '/connected')
                self.server.auth.begin.assert_called_once_with(None)
                self.assertEqual([], blocked)
            finally:
                browser.close()


if __name__ == '__main__':
    unittest.main()
