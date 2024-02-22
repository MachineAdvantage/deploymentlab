#!/usr/bin/env bash
wait-for-it -t 10 db:5432 && \
flask db upgrade && \
flask run
