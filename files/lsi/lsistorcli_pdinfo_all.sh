#!/bin/bash

# получаем имя диска
PDNAME=$1

# формируем данные физического диска
echo "storcli $PDNAME show all j" | bash
