#!/usr/local/bin/bash

# Check if argument is provided
if [ $# -ne 1 ]; then
    echo "Usage: $0 <number>"
    echo "Example: $0 1"
    exit 1
fi

# Get the number argument
num=$1

# Validate that it's a number between 1 and 99
if ! [[ "$num" =~ ^[0-9]+$ ]] || [ "$num" -lt 1 ] || [ "$num" -gt 99 ]; then
    echo "Error: Argument must be a number between 1 and 99"
    exit 1
fi

# Format the number with leading zeros (e.g., 1 -> 01, 11 -> 11)
if [ "$num" -lt 10 ]; then
    formatted_num="0$num"
else
    formatted_num="$num"
fi

# Find the crash file that starts with id:000XX
crash_file=$(ls crashes/id:0000"$formatted_num"* 2>/dev/null | head -1)

# Check if file was found
if [ -z "$crash_file" ]; then
    echo "Error: No crash file found matching id:000$formatted_num"
    exit 1
fi

echo "Using crash file: $crash_file"

# Set LD_PRELOAD and run tmux with the crash file
export LD_PRELOAD=/lib/libthr.so.3
./tmux -S ./tmux-server < "$crash_file"
echo "./tmux -S ./tmux-server < \"$crash_file\""
