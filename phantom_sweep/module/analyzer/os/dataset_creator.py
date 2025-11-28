"""
Nmap OS Database Parser - Convert nmap-os-db to CSV dataset
Extracts features compatible with our OS Detection scanner
"""
import re
import csv
import os
import requests
from typing import Dict, List, Optional
from collections import defaultdict


class NmapOSDBParser:
    """Parse Nmap OS database and extract ML-ready features"""
    
    def __init__(self, nmap_os_db_path: Optional[str] = None):
        """
        Args:
            nmap_os_db_path: Path to local nmap-os-db file, or None to download
        """
        self.nmap_os_db_path = nmap_os_db_path
        self.fingerprints = []
    
    def download_nmap_db(self) -> str:
        """Download latest nmap-os-db from GitHub"""
        url = "https://raw.githubusercontent.com/nmap/nmap/master/nmap-os-db"
        print("[*] Downloading nmap-os-db from GitHub...")
        
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            db_content = response.text
            
            # Save to file
            with open('nmap-os-db', 'w') as f:
                f.write(db_content)
            
            print(f"[✓] Downloaded {len(db_content)} bytes")
            return 'nmap-os-db'
        
        except Exception as e:
            print(f"[!] Failed to download: {e}")
            print("[*] Please download manually from:")
            print("    https://github.com/nmap/nmap/blob/master/nmap-os-db")
            return None
    
    def parse_database(self) -> List[Dict]:
        """Parse nmap-os-db file and extract fingerprints"""
        
        if not self.nmap_os_db_path:
            self.nmap_os_db_path = self.download_nmap_db()
            if not self.nmap_os_db_path:
                return []
        
        print(f"[*] Parsing {self.nmap_os_db_path}...")
        
        # Try multiple encodings
        encodings = ['utf-8', 'latin-1', 'iso-8859-1', 'cp1252']
        content = None
        success = False
        
        for encoding in encodings:
            try:
                with open(self.nmap_os_db_path, 'r', encoding=encoding, errors='ignore') as f:
                    content = f.read()
                print(f"   ✓ Successfully read file with {encoding} encoding")
                print(f"   ✓ File size: {len(content):,} characters")
                success = True
                break
            except Exception as e:
                print(f"   ✗ Failed with {encoding}: {e}")
                continue
        
        if not success or content is None or len(content) == 0:
            print("[!] Failed to read file or file is empty")
            return []
        
        # Split into fingerprint blocks
        fingerprint_blocks = re.split(r'\n(?=Fingerprint )', content)
        print(f"[*] Found {len(fingerprint_blocks)} potential fingerprint blocks")
        
        for block in fingerprint_blocks:
            if not block.strip() or not block.startswith('Fingerprint'):
                continue
            
            fp = self._parse_fingerprint_block(block)
            if fp:
                self.fingerprints.append(fp)
        
        print(f"[✓] Parsed {len(self.fingerprints)} fingerprints")
        return self.fingerprints
    
    def _parse_fingerprint_block(self, block: str) -> Optional[Dict]:
        """Parse a single fingerprint block"""
        lines = block.strip().split('\n')
        
        if len(lines) < 2:
            return None
        
        # First line: Fingerprint <OS Name>
        os_name_match = re.match(r'Fingerprint (.+)', lines[0])
        if not os_name_match:
            return None
        
        os_name = os_name_match.group(1).strip()
        
        # Second line: Class <vendor> | <os_family> | <os_gen> | <device_type>
        class_match = re.match(r'Class (.+)', lines[1])
        if not class_match:
            return None
        
        class_parts = [p.strip() for p in class_match.group(1).split('|')]
        
        fingerprint = {
            'os_name': os_name,
            'vendor': class_parts[0] if len(class_parts) > 0 else 'Unknown',
            'os_family': class_parts[1] if len(class_parts) > 1 else 'Unknown',
            'os_generation': class_parts[2] if len(class_parts) > 2 else 'Unknown',
            'device_type': class_parts[3] if len(class_parts) > 3 else 'general purpose',
        }
        
        # Parse test results (SEQ, OPS, WIN, ECN, T1-T7, U1, IE)
        test_data = {}
        for line in lines[2:]:
            if '=' in line:
                # Extract test name and values
                test_parts = line.split('(', 1)
                if len(test_parts) == 2:
                    test_name = test_parts[0].strip()
                    test_values = test_parts[1].rstrip(')')
                    test_data[test_name] = test_values
        
        # Extract specific features we need for our model
        features = self._extract_features(test_data)
        fingerprint.update(features)
        
        return fingerprint
    
    def _extract_features(self, test_data: Dict[str, str]) -> Dict:
        """Extract ML features from Nmap test data"""
        
        features = {
            'ttl': None,
            'window_size': None,
            'df_flag': None,
            'tcp_options': None,
            'ip_id_sequence': None,
            'icmp_response': None,
        }
        
        # Extract TTL from T1 test (SYN to open port)
        if 'T1' in test_data:
            ttl_match = re.search(r'T=([0-9A-F]+)', test_data['T1'])
            if ttl_match:
                try:
                    features['ttl'] = int(ttl_match.group(1), 16)
                except:
                    pass
        
        # Extract Window size from WIN test
        if 'WIN' in test_data:
            win_match = re.search(r'W1=([0-9A-F]+)', test_data['WIN'])
            if win_match:
                try:
                    features['window_size'] = int(win_match.group(1), 16)
                except:
                    pass
        
        # Extract DF flag from T1 test
        if 'T1' in test_data:
            df_match = re.search(r'DF=([YN])', test_data['T1'])
            if df_match:
                features['df_flag'] = 1 if df_match.group(1) == 'Y' else 0
        
        # Extract TCP options from OPS test
        if 'OPS' in test_data:
            features['tcp_options'] = test_data['OPS'][:100]  # Truncate
        
        # Extract IP ID sequence from SEQ test
        if 'SEQ' in test_data:
            if 'TI=I' in test_data['SEQ']:
                features['ip_id_sequence'] = 'incremental'
            elif 'TI=RI' in test_data['SEQ']:
                features['ip_id_sequence'] = 'random'
            elif 'TI=Z' in test_data['SEQ']:
                features['ip_id_sequence'] = 'constant'
        
        # Check ICMP response from IE test
        if 'IE' in test_data:
            features['icmp_response'] = 1 if 'R=Y' in test_data['IE'] else 0
        
        return features
    
    def save_to_csv(self, output_file: str = 'nmap_os_dataset.csv'):
        """Save parsed fingerprints to CSV for ML training"""
        
        if not self.fingerprints:
            print("[!] No fingerprints to save. Run parse_database() first.")
            return
        
        print(f"[*] Saving to {output_file}...")
        
        # Define CSV columns
        columns = [
            'os_name',
            'os_family',
            'vendor',
            'os_generation',
            'device_type',
            'ttl',
            'window_size',
            'df_flag',
            'tcp_options',
            'ip_id_sequence',
            'icmp_response',
        ]
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=columns, extrasaction='ignore')
            writer.writeheader()
            
            for fp in self.fingerprints:
                # Filter out fingerprints with too many missing features
                valid_features = sum(1 for k in columns[5:] if fp.get(k) is not None)
                if valid_features >= 3:  # At least 3 features must be present
                    writer.writerow(fp)
        
        print(f"[✓] Saved dataset to {output_file}")
        
        # Print statistics
        self._print_statistics()
    
    def _print_statistics(self):
        """Print dataset statistics"""
        os_families = defaultdict(int)
        vendors = defaultdict(int)
        
        for fp in self.fingerprints:
            os_families[fp.get('os_family', 'Unknown')] += 1
            vendors[fp.get('vendor', 'Unknown')] += 1
        
        print("\n[*] Dataset Statistics:")
        print(f"    Total fingerprints: {len(self.fingerprints)}")
        print(f"\n    Top OS Families:")
        for os_fam, count in sorted(os_families.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"      {os_fam}: {count}")
        
        print(f"\n    Top Vendors:")
        for vendor, count in sorted(vendors.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"      {vendor}: {count}")


def main():
    """Main function to create dataset"""
    print("="*60)
    print("Nmap OS Database → ML Dataset Converter")
    print("="*60)
    print()
    
    # Try to open nmap-os-db.txt directly
    try:
        with open('nmap-os-db.txt', 'r', encoding='utf-8', errors='ignore') as f:
            # Just check if file can be opened
            _ = f.read(100)  # Read first 100 chars to verify
            print(f)
        print(f)
        print(f"[✓] Found file: nmap-os-db.txt")
        parser = NmapOSDBParser(nmap_os_db_path='nmap-os-db.txt')
        
    except FileNotFoundError:
        # If nmap-os-db.txt not found, try alternatives
        print("[!] nmap-os-db.txt not found")
        print("[*] Searching for alternatives...")
        
        local_paths = [
            'nmap-os-db',
            '/usr/share/nmap/nmap-os-db',
            '/usr/local/share/nmap/nmap-os-db',
        ]
        
        local_file = None
        for path in local_paths:
            if os.path.exists(path):
                local_file = path
                print(f"[✓] Found: {path}")
                break
        
        if local_file:
            parser = NmapOSDBParser(nmap_os_db_path=local_file)
        else:
            print("[*] No local file found, downloading from GitHub...")
            parser = NmapOSDBParser()
    
    # Parse the database
    print()
    fingerprints = parser.parse_database()
    
    if not fingerprints or len(fingerprints) == 0:
        print("\n[!] No fingerprints parsed!")
        print("\n💡 Troubleshooting:")
        print("   - Check if file contains 'Fingerprint' lines")
        print("   - Try opening file in text editor to verify format")
        print("   - Download fresh copy: https://github.com/nmap/nmap/blob/master/nmap-os-db")
        return
    
    # Save to CSV
    parser.save_to_csv('nmap_os_dataset.csv')
    
    print("\n[✓] Dataset created successfully!")
    print(f"[*] Output: nmap_os_dataset.csv")
    print(f"[*] Total samples: {len(fingerprints)}")
    print("\n[*] Next steps:")
    print("    1. Upload 'nmap_os_dataset.csv' to Google Colab")
    print("    2. Open and run 'OS_Detection_Training.ipynb'")
    print("    3. Download the trained model files")


if __name__ == '__main__':
    main()