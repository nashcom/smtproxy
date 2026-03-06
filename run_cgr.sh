docker stop smtproxy
docker rm smtproxy
docker run -d --name smtproxy -p 1025:1025 -p 1465:1465 --env-file .env -v ./tls:/tls nashcom/smtproxy:cgr

sleep 2
docker logs smtproxy
