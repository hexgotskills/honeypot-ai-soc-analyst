SEVERITY = {'low': 1, 'medium': 2, 'high': 3}

def incident_severity(detections):
    if not detections:
        return 'low'
    max_sev = max(SEVERITY.get(d.get('severity'), 0) for d in detections)
    # Count distinct rule groups (prefix before '-')
    groups = {d['rule_id'].split('-')[0] for d in detections}
    if len(groups) >= 2:
        # bump one level up, max to high
        for level in ['low', 'medium', 'high']:
            if SEVERITY[level] > max_sev:
                max_sev = SEVERITY[level]
                break
    # Return word matching max_sev
    for name, val in SEVERITY.items():
        if val == max_sev:
            return name
    return 'low'