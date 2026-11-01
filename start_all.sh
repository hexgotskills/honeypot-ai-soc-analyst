#!/usr/bin/env bash
set -e
source .venv/bin/activate
trap 'kill 0' INT TERM
python -m honeypot.tcp_decoy > data/tcp.log 2>&1 &
python -m honeypot.http_decoy > data/http.log 2>&1 &
python worker.py > data/worker.log 2>&1 &
python app.py > data/dashboard.log 2>&1 &
wait

