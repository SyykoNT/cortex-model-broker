import copy
import json
import unittest
from types import SimpleNamespace
from cortex_broker.protocol import reconstruct_sse, Refusal
from cortex_broker.auth import AuthError
from cortex_broker.admin import Controller


class ReassemblyTests(unittest.TestCase):
    def fixture(self):
        item={'id':'fc_fixture','type':'function_call','call_id':'call_fixture',
              'name':'fixture','arguments':'{}','status':'completed'}
        return [{'type':'response.output_item.added','output_index':0,
                 'item':{**item,'arguments':'','status':'in_progress'}},
                {'type':'response.output_item.done','output_index':0,'item':item},
                {'type':'response.completed','response':{'id':'resp_fixture','status':'completed','output':[]}}]
    def parse(self,events):
        return reconstruct_sse(''.join('data: '+json.dumps(e)+'\n\n' for e in events))
    def test_complete_items_reassemble_without_modifying_events(self):
        events=self.fixture();p=self.parse(events)
        self.assertTrue(p['complete']);self.assertEqual([events[1]['item']],p['response']['output'])
        self.assertEqual([],p['events'][-1]['response']['output'])
        self.assertEqual(events,p['events'])
    def test_populated_terminal_matches_exactly(self):
        events=self.fixture();events[-1]['response']['output']=[copy.deepcopy(events[1]['item'])]
        self.assertTrue(self.parse(events)['complete'])
        events[-1]['response']['output'][0]['arguments']='{"changed":true}'
        self.assertFalse(self.parse(events)['complete'])
    def test_gaps_duplicates_changed_id_and_missing_done_refused(self):
        original=self.fixture();cases=[]
        e=copy.deepcopy(original);e[1]['output_index']=1;cases.append(e)
        e=copy.deepcopy(original);e.insert(2,copy.deepcopy(e[1]));cases.append(e)
        e=copy.deepcopy(original);e[1]['item']['id']='other';cases.append(e)
        e=copy.deepcopy(original);e.pop(1);cases.append(e)
        e=copy.deepcopy(original);e[1]['output_index']=True;cases.append(e)
        for e in cases:
            with self.subTest(e=e):self.assertFalse(self.parse(e)['complete'])
    def test_finite_refresh_time_captured_only_for_matching_reason(self):
        for reason,value,included in [('refresh_not_yet_allowed',2000000000.0,True),
                ('refresh_not_yet_allowed',float('inf'),False),
                ('refresh_not_yet_allowed',True,False),('sign_in_required',2000000000,False)]:
            rows=[]
            def access(**kw):raise AuthError(reason,retry_at=value)
            c=Controller(SimpleNamespace(access=access),None,
                transport=SimpleNamespace(capture=SimpleNamespace(append=lambda run,kind,data:rows.append((kind,data)))))
            with self.assertRaises(Refusal):c._dispatch({'version':1,'command':'refresh'})
            self.assertEqual(included,'retry_at' in rows[-1][1])
