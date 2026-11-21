import pathlib, tempfile, unittest
from unittest.mock import patch
from locdepintel import core

class VersionSixTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.patch=patch.object(core,'home_data',return_value=pathlib.Path(self.tmp.name))
        self.patch.start()
    def tearDown(self):self.patch.stop();self.tmp.cleanup()
    def seed(self):
        with core.db() as con:
            for i in range(3):
                path=f'/tmp/project-{i}/.venv'
                con.execute('INSERT INTO envs VALUES (?,?,?,?,?)',(path,'Python','2026-11-10','monitored',1))
                con.execute('INSERT INTO inventory VALUES (?,?,?,?,?,?,?,1)',(path,'PyPI','urllib3','2.2.2','unknown','2026-11-10','2026-11-10'))
                con.execute('INSERT INTO findings(env,ecosystem,name,version,advisory,kind,summary,url,first_seen,last_seen,active) VALUES(?,?,?,?,?,?,?,?,?,?,1)',(path,'PyPI','urllib3','2.2.2','GHSA-test','vulnerability','Test only','https://example.org','2026-11-10','2026-11-10'))
            con.execute('INSERT INTO scans(started,ended,status,packages) VALUES (?,?,?,?)',('2026-11-10','2026-11-10','ok',3))
            con.execute('INSERT INTO checks(timestamp,state,note,packages) VALUES (?,?,?,?)',('2026-11-10','ok','1 unique advisory',1))
    def test_unique_affected_vs_installations(self):
        self.seed();o=core.overview()
        self.assertEqual(o['stats']['affected_packages'],1)
        self.assertEqual(o['stats']['affected_installations'],3)
        self.assertEqual(o['stats']['installed_entries'],3)
        self.assertIsNone(o['stats']['new_advisory_matches'])
        self.assertEqual(o['action_queue'][0]['installation_count'],3)
    def test_no_inventory_migration(self):
        self.seed(); core.overview()
        with core.db() as con:
            self.assertEqual(con.execute('SELECT count(*) FROM inventory').fetchone()[0],3)
            self.assertEqual(con.execute('SELECT count(*) FROM findings').fetchone()[0],3)
    def test_required_ui_elements(self):
        path=pathlib.Path(__file__).parents[1]/'locdepintel/static'
        html=(path/'index.html').read_text()
        for s in ('view-overview','queue-body','overview-envs','scan-progress','view-action','view-inventory','view-pulse','settings-dialog'):
            self.assertIn('id="'+s+'"',html)
