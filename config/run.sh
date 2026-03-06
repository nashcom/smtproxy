docker stop smtproxy
docker rm smtproxy
docker run -d --name smtproxy -p 1025:1025 -p 1465:1465 -v ./key.pem:/tls/tls.key -v ./cert.pem:/tls/tls.crt smtproxy

sleep 2
docker logs smtproxy
