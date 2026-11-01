import sys
import os

# Add project root to path so imports work.
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

from database.db import get_recent_events

def main():
    events = get_recent_events(20)
    for ev in events:
        # Print selected fields in a simple line.
        print(f"{ev.get('id')}: {ev.get('timestamp')} {ev.get('source_ip')} {ev.get('service')} {ev.get('event_type')} {ev.get('outcome')} {ev.get('metadata')}")

if __name__ == '__main__':
    main()
