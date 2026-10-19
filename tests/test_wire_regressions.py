import json
import unittest
from cortex_broker.admin import Controller
from cortex_broker.auth import AuthError
from cortex_broker.fc5 import first_request
from cortex_broker.protocol import Refusal, adapt


class WireRegressionTests(unittest.TestCase):
    def test_generated_namespace_has_provider_required_description(self):
        request = first_request()
        out, _ = adapt(request)
        namespace = out['tools'][0]
        self.assertEqual('namespace', namespace['type'])
        self.assertEqual('Tools provided by the caller.', namespace['description'])
        self.assertEqual(request['tools'], namespace['tools'])
        self.assertNotIn('namespace', json.dumps(request))

    def test_existing_namespace_preserved(self):
        request = first_request()
        request['tools'] = [{'type': 'namespace', 'name': 'custom',
                             'description': 'Caller description', 'tools': request['tools']}]
        out, _ = adapt(request)
        self.assertEqual(request['tools'], out['tools'])

    def test_refresh_error_diagnostic_is_closed_and_no_token_reads(self):
        class Auth:
            error = ""
            def access(self, force_refresh=False):
                assert force_refresh
                raise AuthError(self.error)
        auth = Auth()
        controller = Controller(auth, None)
        rows = []
        controller.captured = lambda run, kind, value: rows.append((kind, value))
        for error, expected in [('refresh_not_yet_allowed', 'refresh_not_yet_allowed'),
                                ('provider_request_failed', 'provider_request_failed'),
                                ('arbitrary private provider message', 'auth_failure')]:
            auth.error = error
            rows.clear()
            with self.assertRaisesRegex(Refusal, '^operation_failed$'):
                controller._dispatch({'version': 1, 'command': 'refresh'})
            self.assertEqual([('admin.refresh', {'command': 'refresh'}),
                              ('admin.refresh.refused', {'reason': expected})], rows)

    def test_refresh_capture_failure_does_not_retry(self):
        class Auth:
            calls = 0
            def access(self, force_refresh=False):
                self.calls += 1
                raise AuthError('provider_request_failed')
        auth = Auth()
        controller = Controller(auth, None)
        def capture(run, kind, value):
            if kind == 'admin.refresh.refused':
                raise Refusal('capture_unavailable')
        controller.captured = capture
        with self.assertRaisesRegex(Refusal, 'capture_unavailable'):
            controller._dispatch({'version': 1, 'command': 'refresh'})
        self.assertEqual(1, auth.calls)
