docker stop postfix
docker rm postfix

CONTAINER_IMAGE=boky/postfix:latest-alpine

docker run -d \
  --name postfix \
  --hostname mail.example.com \
  --env-file postfix.env \
  -p 2525:25 \
  -v /tls:/tls \
  "$CONTAINER_IMAGE"

sleep 2
docker logs postfix

