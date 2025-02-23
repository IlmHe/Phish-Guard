#!/bin/bash

npx webpack --watch &
web-ext run --source-dir dist --reload