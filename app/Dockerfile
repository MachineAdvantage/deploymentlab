# # Use the official Python image as the base image
# FROM python:3.11

# # Wait for the database to be ready
# RUN apt-get update
# RUN apt-get install -y wait-for-it

# # Install Poetry & waitress for serving the app
# RUN pip install poetry
# RUN pip install waitress

# # Set the working directory in the container
# WORKDIR /app

# # Copy the poetry.lock and pyproject.toml files to the container
# COPY poetry.lock /app/
# COPY pyproject.toml /app/

# # Install project dependencies TODO THIS ISNT WORKING
# # RUN poetry install --no-dev
# RUN poetry export -o requirements.txt
# RUN pip install -r requirements.txt

# # Copy the rest of the application code to the container
# COPY . /app

# # Expose the port on which the Flask app will run
# # EXPOSE 5000

# # CMD sh ./entrypoint.dev.sh
# CMD sh ./entrypoint_flask.sh

# # Set the environment variables
# # ENV FLASK_APP=aitestmycode
# # ENV FLASK_RUN_HOST=0.0.0.0

# # Run the Flask app
# # CMD ["poetry", "run", "flask", "run"]

FROM python:3.10

RUN apt-get update
RUN apt-get install -y wait-for-it
RUN pip install poetry
RUN pip install waitress
COPY . /app
WORKDIR /app
RUN poetry export -o requirements.txt
RUN pip install -r requirements.txt
ENV PYTHONPATH "${PYTHONPATH}:/app/"

RUN ls ; pwd ; echo $PATH; echo $PYTHONPATH


# # Set the environment variables
# ENV FLASK_APP=app
# ENV FLASK_RUN_HOST=0.0.0.0
# CMD ["poetry", "run", "flask", "run"]

# CMD ["/bin/bash", "-it"]

CMD sh -c ./entrypoint.sh
