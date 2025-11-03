Press CTRL+C to quit
2025-11-03 14:45:16.027 | INFO     | __main__:wait_for_next_totp_window:114 - Waiting 16.0s for fresh TOTP window
127.0.0.1 - - [03/Nov/2025 14:45:26] "GET / HTTP/1.1" 200 -
127.0.0.1 - - [03/Nov/2025 14:45:26] "GET /historic HTTP/1.1" 200 -
2025-11-03 14:45:32.001 | INFO     | __main__:gen_auth_token:214 - Auth URL: https://api-t1.fyers.in/api/v3/generate-authcode?client_id=1BE74FZNXA-100&redirect_uri=http%3A%2F%2F127.0.0.1%3A8081&response_type=code&state=None
2025-11-03 14:45:32.645 | INFO     | __main__:verify_totp:134 - Verifying TOTP with request_key: eyJhbGciOiJIUzI...
2025-11-03 14:45:35.950 | INFO     | __main__:gen_auth_token:259 - Authentication successful
2025-11-03 14:45:36.841 | INFO     | __main__:get_hist:323 - Historical candles appended. Total count: 375
2025-11-03 14:45:36.889 | INFO     | __main__:replay_feed:413 - Loaded 41399 ticks from /var/lib/data/apr03.csv
2025-11-03 14:45:37.917 | INFO     | __main__:replay_feed:433 - Processed 0 ticks
127.0.0.1 - - [03/Nov/2025 14:45:38] "GET / HTTP/1.1" 200 -
2025-11-03 14:45:38.015 | ERROR    | __main__:ws_endpoint:478 - WebSocket error: Connection closed: 1001 
127.0.0.1 - - [03/Nov/2025 14:45:38] "GET /ws HTTP/1.1" 200 -
127.0.0.1 - - [03/Nov/2025 14:45:38] "GET /historic HTTP/1.1" 200 -
127.0.0.1 - - [03/Nov/2025 14:46:18] "GET / HTTP/1.1" 200 -
2025-11-03 14:46:18.315 | ERROR    | __main__:ws_endpoint:478 - WebSocket error: Connection closed: 1001 
127.0.0.1 - - [03/Nov/2025 14:46:18] "GET /ws HTTP/1.1" 200 -
127.0.0.1 - - [03/Nov/2025 14:46:18] "GET /historic HTTP/1.1" 200 -
