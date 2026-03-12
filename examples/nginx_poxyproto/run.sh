docker run --name nginx -d --network host -v $(pwd)/nginx.conf:/etc/nginx/nginx.conf:ro nginx:alpine
