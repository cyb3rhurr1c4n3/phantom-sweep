"""
Comprehensive Defender Testing Suite
"""
import socket
import time
import random
from typing import List, Tuple
from scapy.all import IP, TCP, send, conf

conf.verb = 0


class DefenderTester:
    """Test defender false positive/negative rates"""
    
    def __init__(self, target: str, defender_log: str = None):
        self.target = target
        self.defender_log = defender_log
        self.results = {
            'true_positives': 0,
            'false_positives': 0,
            'true_negatives': 0,
            'false_negatives': 0
        }
    
    def test_legitimate_traffic(self, num_requests: int = 50):
        """
        Test 1: Legitimate traffic (should NOT trigger)
        Expected: True Negative
        """
        print(f"\n[Test 1] Legitimate Traffic Test ({num_requests} requests)")
        print("="*60)
        
        detected_count = 0
        
        for i in range(num_requests):
            try:
                # Simulate normal HTTP request
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((self.target, 80))
                sock.send(b"GET / HTTP/1.1\r\nHost: " + self.target.encode() + b"\r\n\r\n")
                sock.recv(1024)
                sock.close()
                
                # Human-like delay
                time.sleep(random.uniform(3, 10))
                
                # Check if detected
                if self._check_detection():
                    detected_count += 1
                    print(f"  [!] Request {i+1}: DETECTED (FALSE POSITIVE)")
                else:
                    print(f"  [✓] Request {i+1}: Not detected")
                    
            except Exception as e:
                print(f"  [x] Request {i+1}: Error - {e}")
        
        false_positive_rate = (detected_count / num_requests) * 100
        print(f"\n[Result] False Positive Rate: {false_positive_rate:.2f}%")
        print(f"         Detected: {detected_count}/{num_requests}")
        
        self.results['false_positives'] += detected_count
        self.results['true_negatives'] += (num_requests - detected_count)
        
        return false_positive_rate
    
    def test_slow_scan(self, ports: List[int], delay: float = 2.0):
        """
        Test 2: Slow port scan (boundary test)
        Expected: Should NOT detect if slow enough
        """
        print(f"\n[Test 2] Slow Scan Test ({len(ports)} ports, {delay}s delay)")
        print("="*60)
        
        detected = False
        open_ports = []
        
        for port in ports:
            try:
                # TCP Connect
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.target, port))
                
                if result == 0:
                    open_ports.append(port)
                    print(f"  [+] Port {port}: OPEN")
                else:
                    print(f"  [-] Port {port}: Closed")
                
                sock.close()
                
                # Check detection
                if self._check_detection():
                    detected = True
                    print(f"  [!] DETECTED after port {port}")
                    break
                
                time.sleep(delay)
                
            except Exception as e:
                print(f"  [x] Port {port}: Error - {e}")
        
        if detected:
            print(f"\n[Result] DETECTED (may be too aggressive)")
            self.results['true_positives'] += 1
        else:
            print(f"\n[Result] NOT DETECTED (good - slow scan should evade)")
            self.results['true_negatives'] += 1
        
        return detected, open_ports
    
    def test_fast_scan(self, ports: List[int]):
        """
        Test 3: Fast aggressive scan (should detect)
        Expected: True Positive
        """
        print(f"\n[Test 3] Fast Scan Test ({len(ports)} ports, no delay)")
        print("="*60)
        
        # Send SYN packets rapidly
        packets = []
        for port in ports:
            pkt = IP(dst=self.target) / TCP(dport=port, flags='S')
            packets.append(pkt)
        
        print(f"  [*] Sending {len(packets)} SYN packets...")
        send(packets, verbose=0, inter=0.001)  # Very fast
        
        time.sleep(2)  # Wait for defender to process
        
        detected = self._check_detection()
        
        if detected:
            print(f"\n[Result] DETECTED ✓ (True Positive - correctly detected attack)")
            self.results['true_positives'] += 1
        else:
            print(f"\n[Result] NOT DETECTED ✗ (False Negative - missed attack!)")
            self.results['false_negatives'] += 1
        
        return detected
    
    def test_medium_scan(self, ports: List[int], delay: float = 0.1):
        """
        Test 4: Medium-speed scan (boundary test)
        """
        print(f"\n[Test 4] Medium Scan Test ({len(ports)} ports, {delay}s delay)")
        print("="*60)
        
        detected = False
        
        for i, port in enumerate(ports):
            pkt = IP(dst=self.target) / TCP(dport=port, flags='S')
            send(pkt, verbose=0)
            
            if (i + 1) % 10 == 0:
                if self._check_detection():
                    detected = True
                    print(f"  [!] DETECTED after {i+1} ports")
                    break
                print(f"  [*] Scanned {i+1}/{len(ports)} ports...")
            
            time.sleep(delay)
        
        if not detected:
            detected = self._check_detection()
        
        print(f"\n[Result] {'DETECTED' if detected else 'NOT DETECTED'}")
        
        if detected:
            self.results['true_positives'] += 1
        else:
            self.results['false_negatives'] += 1
        
        return detected
    def _check_detection(self) -> bool:
        if self.defender_log:
            try:
                with open(self.defender_log,'r') as f:
                    lines=f.readlines()[-20:]

                    for line in lines:
                        if 'BLOCKED' in line or 'DETECTED' in line:
                            import re
                            import datetime

                            match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                            if match:
                                log_time = datetime.datetime.strptime(
                                    match.group(1), '%Y-%m-%d %H:%M:%S'
                            )
                                now = datetime.datetime.now()
                            
                                if (now - log_time).seconds < 30:
                                    return True
            except Exception as e:
                pass
        try:
            import subprocess
            result = subprocess.run(
                ['sudo', 'iptables', '-L', 'INPUT', '-n'],
                capture_output=True,
                text=True,
                timeout=2
            )
            
            # Check if our IP is in DROP rules
            if 'DROP' in result.stdout:
                # Look for specific IP
                import socket
                my_ip = socket.gethostbyname(socket.gethostname())
                if my_ip in result.stdout:
                    return True
        except:
            pass
        blocked_count = 0
        test_ports = [80, 443, 22, 21, 25]
    
        for port in test_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((self.target, port))
                sock.close()
                
                # Connection timeout = might be blocked
                if result == 110:  # Connection timeout
                    blocked_count += 1
            except socket.timeout:
                blocked_count += 1
            except:
                pass
        
        # If majority of ports timeout, likely blocked
        if blocked_count >= 3:
            return True
        
        return False

    def print_summary(self):
        """Print comprehensive test summary"""
        print("\n" + "="*60)
        print("DEFENDER TEST SUMMARY")
        print("="*60)
        
        total = sum(self.results.values())
        
        print(f"\nConfusion Matrix:")
        print(f"  True Positives (TP):  {self.results['true_positives']}")
        print(f"  False Positives (FP): {self.results['false_positives']}")
        print(f"  True Negatives (TN):  {self.results['true_negatives']}")
        print(f"  False Negatives (FN): {self.results['false_negatives']}")
        
        # Calculate metrics
        if self.results['true_positives'] + self.results['false_negatives'] > 0:
            recall = self.results['true_positives'] / (
                self.results['true_positives'] + self.results['false_negatives']
            )
            print(f"\nRecall (Detection Rate): {recall*100:.2f}%")
        
        if self.results['true_positives'] + self.results['false_positives'] > 0:
            precision = self.results['true_positives'] / (
                self.results['true_positives'] + self.results['false_positives']
            )
            print(f"Precision: {precision*100:.2f}%")
        
        if total > 0:
            accuracy = (self.results['true_positives'] + self.results['true_negatives']) / total
            print(f"Accuracy: {accuracy*100:.2f}%")
        
        # False Positive Rate (critical for production)
        if self.results['false_positives'] + self.results['true_negatives'] > 0:
            fpr = self.results['false_positives'] / (
                self.results['false_positives'] + self.results['true_negatives']
            )
            print(f"\n⚠️  False Positive Rate: {fpr*100:.2f}%")
            
            if fpr > 0.05:
                print(f"   ❌ UNACCEPTABLE (>5%)")
            elif fpr > 0.01:
                print(f"   ⚠️  WARNING (1-5%)")
            else:
                print(f"   ✅ ACCEPTABLE (<1%)")


def main():
    """Run comprehensive defender tests"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Test defender performance")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("--log", help="Defender log file path")
    parser.add_argument("--all", action="store_true", help="Run all tests")
    args = parser.parse_args()
    
    tester = DefenderTester(args.target, args.log)
    
    print("="*60)
    print("DEFENDER PERFORMANCE TESTING")
    print("="*60)
    print(f"Target: {args.target}")
    print(f"Log: {args.log or 'Not specified'}")
    
    if args.all:
        # Run all tests
        input("\nPress Enter to start Test 1 (Legitimate Traffic)...")
        tester.test_legitimate_traffic(num_requests=50)
        
        input("\nPress Enter to start Test 2 (Slow Scan)...")
        tester.test_slow_scan(ports=list(range(1, 51)), delay=2.0)
        
        input("\nPress Enter to start Test 3 (Fast Scan)...")
        tester.test_fast_scan(ports=list(range(1, 101)))
        
        input("\nPress Enter to start Test 4 (Medium Scan)...")
        tester.test_medium_scan(ports=list(range(1, 101)), delay=0.1)
    else:
        # Interactive menu
        while True:
            print("\n" + "="*60)
            print("Select Test:")
            print("  1. Legitimate Traffic (False Positive Test)")
            print("  2. Slow Scan (Evasion Test)")
            print("  3. Fast Scan (True Positive Test)")
            print("  4. Medium Scan (Boundary Test)")
            print("  5. Run All Tests")
            print("  6. Print Summary")
            print("  0. Exit")
            
            choice = input("\nChoice: ").strip()
            
            if choice == '1':
                tester.test_legitimate_traffic(num_requests=50)
            elif choice == '2':
                tester.test_slow_scan(ports=list(range(1, 51)), delay=2.0)
            elif choice == '3':
                tester.test_fast_scan(ports=list(range(1, 101)))
            elif choice == '4':
                tester.test_medium_scan(ports=list(range(1, 101)), delay=0.1)
            elif choice == '5':
                tester.test_legitimate_traffic(num_requests=30)
                time.sleep(5)
                tester.test_slow_scan(ports=list(range(1, 31)), delay=2.0)
                time.sleep(5)
                tester.test_medium_scan(ports=list(range(1, 51)), delay=0.1)
                time.sleep(5)
                tester.test_fast_scan(ports=list(range(1, 101)))
            elif choice == '6':
                tester.print_summary()
            elif choice == '0':
                break
    
    tester.print_summary()


if __name__ == "__main__":
    main()