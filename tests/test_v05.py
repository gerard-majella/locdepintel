import json, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
from locdepintel import core

class VersionFiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.patcher=patch.object(core,'home_data',return_value=Path(self.tmp.name))
        self.patcher.start()
    def tearDown(self):
        self.patcher.stop();self.tmp.cleanup()
    def seed(self):
        with core.db() as conn:
            for env in ('/tmp/project-a/.venv','/tmp/project-b/.venv','/tmp/project-c/.venv'):
                conn.execute('INSERT INTO inventory VALUES(?,?,?,?,?,?,?,1)',(env,'PyPI','urllib3','2.2.2','unknown','2026-11-10','2026-11-10'))
            for i,env in enumerate(('/tmp/project-a/.venv','/tmp/project-b/.venv','/tmp/project-c/.venv')):
                conn.execute('INSERT INTO findings(env,ecosystem,name,version,advisory,kind,summary,url,first_seen,last_seen,active) VALUES(?,?,?,?,?,?,?,?,?,?,1)',(env,'PyPI','urllib3','2.2.2','GHSA-test-one','vulnerability','Demo advisory','https://osv.dev/a','2026-11-10','2026-11-10'))
            conn.execute('INSERT INTO findings(env,ecosystem,name,version,advisory,kind,summary,url,first_seen,last_seen,active) VALUES(?,?,?,?,?,?,?,?,?,?,1)',('/tmp/project-a/.venv','PyPI','urllib3','2.2.2','GHSA-test-two','vulnerability','Second advisory','https://osv.dev/b','2026-11-10','2026-11-10'))
    def test_group_aggregation_preserves_locations(self):
        self.seed();groups=core.grouped_findings()
        self.assertEqual(len(groups),1)
        g=groups[0];self.assertEqual(g['advisory_count'],2);self.assertEqual(g['installation_count'],3)
        self.assertEqual(len(g['advisories'][0]['locations']),3)
    def test_pulse_version_match_only_from_existing_finding(self):
        self.seed()
        raw={'ghsa_id':'GHSA-test-one','type':'reviewed','severity':'high','summary':'Demo advisory','published_at':'2026-11-10T11:00:00Z','vulnerabilities':[{'package':{'ecosystem':'pip','name':'urllib3'},'vulnerable_version_range':'<2.3'}]}
        other={'ghsa_id':'GHSA-test-three','type':'reviewed','severity':'high','summary':'Different advisory','published_at':'2026-11-10T12:00:00Z','vulnerabilities':[{'package':{'ecosystem':'pip','name':'urllib3'},'vulnerable_version_range':'<2.3'}]}
        with patch.object(core.urllib.request,'urlopen') as req:
            def response(_req,timeout):
                import io
                if 'type=malware' in _req.full_url:return io.BytesIO(b'[]')
                return io.BytesIO(json.dumps([raw,other]).encode())
            req.side_effect=response
            r=core.sync_pulse()
        self.assertEqual(r['state'],'ok')
        entries={x['id']:x for x in core.pulse()['advisories']}
        self.assertEqual(entries['GHSA-test-one']['local_status'],'affected')
        self.assertEqual(entries['GHSA-test-three']['local_status'],'package-present')
    def test_feed_failure_keeps_existing_cache(self):
        self.seed()
        with core.db() as con:
            con.execute('INSERT INTO pulse_advisories VALUES(?,?,?,?,?,?,?,?,?)',('GHSA-existing','malware','critical','Previously fetched','https://github.com/advisories/GHSA-existing','2026-11-10','2026-11-10','2026-11-10',json.dumps([{'ecosystem':'npm','name':'bad-package','range':'*','fixed':''}])))
        with patch.object(core.urllib.request,'urlopen',side_effect=OSError('offline')):
            result=core.sync_pulse()
        self.assertEqual(result['state'],'error')
        self.assertEqual(len(core.pulse()['advisories']),1)
    def test_ui_uses_single_shared_engine(self):
        js=(Path(__file__).parents[1]/'locdepintel/static/app.js').read_text()
        html=(Path(__file__).parents[1]/'locdepintel/static/index.html').read_text()
        self.assertIn('grouped-findings',js)
        self.assertIn('pulse-sync',js)
        self.assertIn('inv-env',html)
        self.assertNotIn('id="env-list"',html)

if __name__=='__main__':unittest.main()
