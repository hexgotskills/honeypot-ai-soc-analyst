import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import csv, time, sys
import config
from database.db import get_connection
# add project root to sys.path for import
import os
sys.path.append(os.path.abspath(os.path.dirname(__file__) + '/..'))
from scripts.simulate_events import run_scenario

EXPECTED = {
    'T1': (set(), 0),
    'T2': ({'AUTH-001'}, 1),
    'T3': (set(), 0),
    'T4': ({'AUTH-001','WEB-002','COMBO-001'}, 1),
    'T5': (set(), 0),
}
RULES = {'AUTH-001','WEB-001','WEB-002','COMBO-001'}

print('Database path:', config.DATABASE_PATH)
ans = input('This erases all data in this database. Type yes:')
if ans.strip().lower() != 'yes':
    sys.exit(0)

out_path = 'results.csv'
with open(out_path, 'w', newline='') as f:
    w = csv.writer(f)
    w.writerow(['scenario','events_generated','expected_rules','actual_rules','expected_incidents','actual_incidents','result'])
    for scen in ['T1','T2','T3','T4','T5']:
        conn = get_connection()
        cur = conn.cursor()
        for tbl in ('events','detections','incidents','incident_events','ai_reports','blocklist'):
            cur.execute(f'DELETE FROM {tbl}')
        cur.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('auto_block', 'off')")
        conn.commit()
        conn.close()
        run_scenario(scen)
        time.sleep(12)
        conn = get_connection()
        cur = conn.cursor()
        ev_cnt = cur.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        act_rules = set(r[0] for r in cur.execute('SELECT rule_id FROM detections'))
        inc_cnt = cur.execute('SELECT COUNT(*) FROM incidents').fetchone()[0]
        exp_rules, exp_inc = EXPECTED[scen]
        result = 'PASS' if act_rules==exp_rules and inc_cnt==exp_inc else 'FAIL'
        w.writerow([scen, ev_cnt, ';'.join(sorted(exp_rules)), ';'.join(sorted(act_rules)), exp_inc, inc_cnt, result])
        conn.close()

# print table
with open(out_path) as f:
    print(f.read())

# compute metrics
TP=FP=FN=TN=0
for scen, (exp_rules, _) in EXPECTED.items():
    # get actual rules again
    conn = get_connection()
    act_rules = set(r[0] for r in conn.cursor().execute('SELECT rule_id FROM detections'))
    for r in RULES:
        exp = r in exp_rules
        act = r in act_rules
        if exp and act:
            TP+=1
        elif not exp and act:
            FP+=1
        elif exp and not act:
            FN+=1
        else:
            TN+=1
    conn.close()
print('TP',TP,'FP',FP,'FN',FN,'TN',TN)
prec = TP/(TP+FP) if TP+FP else 0
rec = TP/(TP+FN) if TP+FN else 0
print('precision',prec,'recall',rec)

