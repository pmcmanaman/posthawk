.PHONY: build-backend build-frontend run test clean

build-backend:
	docker build -t posthawk-backend .

build-frontend:
	cd frontend && docker build -t posthawk-frontend .

run: build-backend build-frontend
	docker run -d -p 8080:8080 --name posthawk-backend posthawk-backend
	docker run -d -p 3000:80 --name posthawk-frontend posthawk-frontend

test:
	go test ./...

clean:
	docker stop posthawk-backend posthawk-frontend
	docker rm posthawk-backend posthawk-frontend
	rm -rf frontend/dist
