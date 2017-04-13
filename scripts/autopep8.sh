#!/bin/bash

LIBFILES="$(find ./lif_n2n -name '*.py' | tr '\n' ' ')"

autopep8 -ia --ignore=E501 ${LIBFILES}
