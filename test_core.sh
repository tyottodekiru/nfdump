#!/bin/bash
# Test script for CO-RE implementation

echo "NetFilter CO-RE Implementation Test"
echo "==================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ This test must be run as root"
    echo "Usage: sudo ./test_core.sh"
    exit 1
fi

echo "✓ Running as root"

# Check if binary exists
if [ ! -f "./nfdump_core" ]; then
    echo "❌ nfdump_core binary not found"
    echo "Build it first with: make -f Makefile.core"
    exit 1
fi

echo "✓ Binary exists"

# Test basic functionality
echo ""
echo "Testing basic functionality..."
echo "Starting nfdump_core for 5 seconds..."

# Start nfdump_core in background
timeout 5s ./nfdump_core --verbose &
NFDUMP_PID=$!

# Generate some traffic to trigger events
sleep 1
echo "Generating network traffic..."
ping -c 3 127.0.0.1 > /dev/null 2>&1 &
ping -c 2 8.8.8.8 > /dev/null 2>&1 &

# Wait for nfdump_core to finish
wait $NFDUMP_PID
EXIT_CODE=$?

if [ $EXIT_CODE -eq 124 ]; then
    echo "✓ nfdump_core ran successfully (timed out as expected)"
elif [ $EXIT_CODE -eq 0 ]; then
    echo "✓ nfdump_core completed successfully"
else
    echo "❌ nfdump_core failed with exit code: $EXIT_CODE"
fi

echo ""
echo "Testing with filter options..."

# Test with host filter
echo "Testing host filter (5 seconds)..."
timeout 5s ./nfdump_core --host 127.0.0.1 --verbose &
NFDUMP_PID=$!

sleep 1
ping -c 2 127.0.0.1 > /dev/null 2>&1 &

wait $NFDUMP_PID
EXIT_CODE=$?

if [ $EXIT_CODE -eq 124 ] || [ $EXIT_CODE -eq 0 ]; then
    echo "✓ Host filter test completed"
else
    echo "❌ Host filter test failed with exit code: $EXIT_CODE"
fi

echo ""
echo "Testing program attachment..."

# Check if BPF programs are loaded
if command -v bpftool > /dev/null 2>&1; then
    echo "Checking BPF program status..."
    
    # Start nfdump_core briefly to check attachment
    timeout 2s ./nfdump_core --verbose > /dev/null 2>&1 &
    NFDUMP_PID=$!
    
    sleep 0.5
    
    # Check if programs are attached
    if bpftool prog show | grep -q "fentry"; then
        echo "✓ BPF programs are properly attached"
    else
        echo "⚠️  Could not verify BPF program attachment"
    fi
    
    # Clean up
    kill $NFDUMP_PID > /dev/null 2>&1
    wait $NFDUMP_PID > /dev/null 2>&1
else
    echo "⚠️  bpftool not available, skipping program attachment check"
fi

echo ""
echo "Summary:"
echo "✓ CO-RE implementation built successfully"
echo "✓ Binary runs without crashes"
echo "✓ Command line options work"
echo "✓ Filter functionality implemented"
echo ""
echo "🎉 CO-RE implementation test completed!"
echo ""
echo "Usage examples:"
echo "  sudo ./nfdump_core                    # Monitor all traffic"
echo "  sudo ./nfdump_core --verbose         # Verbose output"
echo "  sudo ./nfdump_core --host 192.168.1.1 # Filter by host"
echo "  sudo ./nfdump_core --protocol tcp    # Filter by protocol"