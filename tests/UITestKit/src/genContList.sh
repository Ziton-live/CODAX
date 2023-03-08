#!/bin/bash

sudo docker compose build  
sudo docker compose up &
echo "Containers up and running"
sleep 5

containers=$(docker ps --all --no-trunc --format="{{json . }}" | jq -s --tab .)
container_array="$containers"

echo $container_array > containers.json
echo "Snapshot: $container_array"
npm run dev > /dev/null 2>&1 &
while true; do
  read -p "Refresh the list(y/n) (or 'q' to quit): " value
  if [ "$value" == "q" ]; then
    break
  fi
  
  if [ "$value" == "y" ]; then
    containers=$(docker ps --all --no-trunc --format="{{json . }}" | jq -s --tab .)
    container_array="$containers"
    echo "Container lists are updated: $container_array"
  fi
done

cleanup() {
  echo "Cleaning up..."
  pkill -P $$ # kill all child processes
}
trap cleanup EXIT

