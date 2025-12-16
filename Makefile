.PHONY: setup run docker-build docker-run docker-clean

setup:
	python3 -m venv venv
	. venv/bin/activate && pip3 install -r requirements.txt

run:
	. venv/bin/activate && python3 app.py

docker-clean:
	docker stop app || true
	docker rm app || true
	docker rmi app || true

docker-build: docker-clean
	docker build -t app .

docker-run: docker-build
	docker run -d --name app -p 8000:8000 app
