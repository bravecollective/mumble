#!/bin/bash

echo "__import__('brave.mumble.service').mumble.service.main('ICE_SECRET_WRITE')" | paster shell local.ini

