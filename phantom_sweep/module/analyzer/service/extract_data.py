"""
Generate synthetic training data from service_probes.db
"""
import re
import random
from typing import List, Tuple

def generate_synthetic_dataset(service_probes_path: str, num_samples: int = 50000) -> List[Tuple]:
    """
    Generate synthetic banners from service_probes.db patterns
    
    Returns:
        List of (banner, service_name, confidence)
    """
    dataset = []
    
    # Parse service_probes.db
    with open(service_probes_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    # Extract all match patterns
    # Format: match <service> m|<pattern>| p/<product>/ v/<version>/
    matches = re.findall(
        r'match\s+(\S+)\s+m\|([^|]+)\|(?:\w*)\s+p/([^/]*)/(?:\s+v/([^/]*)/)?' ,
        content
    )
    
    service_patterns = {}
    for service, pattern, product, version in matches:
        if service not in service_patterns:
            service_patterns[service] = []
        service_patterns[service].append({
            'pattern': pattern,
            'product': product,
            'version': version or ''
        })
    
    print(f"[*] Extracted {len(service_patterns)} services")
    
    # Generate synthetic samples
    for service, patterns in service_patterns.items():
        # Generate multiple samples per service
        samples_per_service = max(10, num_samples // len(service_patterns))
        
        for _ in range(samples_per_service):
            pattern_data = random.choice(patterns)
            
            # Create synthetic banner
            banner = create_banner_from_pattern(
                pattern_data['pattern'],
                pattern_data['product'],
                pattern_data['version']
            )
            
            if banner:
                dataset.append({
                    'banner': banner,
                    'service': service,
                    'product': pattern_data['product'],
                    'version': pattern_data['version']
                })
    
    print(f"[*] Generated {len(dataset)} training samples")
    return dataset


def create_banner_from_pattern(pattern: str, product: str, version: str) -> str:
    """
    Create realistic banner from regex pattern
    
    Example:
        pattern: "SSH-2\\.0-OpenSSH_(\\d+\\.\\d+)"
        product: "OpenSSH"
        version: "7.4"
        → banner: "SSH-2.0-OpenSSH_7.4"
    """
    try:
        # Remove regex special chars and create realistic banner
        banner = pattern
        
        # Replace common regex patterns with actual values
        banner = banner.replace('\\r\\n', '\r\n')
        banner = banner.replace('\\n', '\n')
        banner = banner.replace('\\t', '\t')
        banner = banner.replace('\\d+', ''.join([str(random.randint(0, 9)) for _ in range(2)]))
        banner = banner.replace('\\w+', 'server')
        banner = banner.replace('[^\\r\\n]+', 'hostname')
        banner = banner.replace('.*', product)
        banner = banner.replace('.+', product)
        banner = re.sub(r'\\x[0-9a-f]{2}', '', banner)  # Remove hex escapes
        banner = re.sub(r'[\[\]\(\)\{\}\^\$\*\+\?\.]', '', banner)  # Remove regex chars
        
        # Add version if available
        if version:
            banner = banner.replace(version, version)
        
        return banner[:500]  # Limit length
        
    except:
        return None


# Usage
dataset = generate_synthetic_dataset('phantom_sweep/module/analyzer/service/service_probes.db', num_samples=50000)

# Save to CSV
import pandas as pd
df = pd.DataFrame(dataset)
df.to_csv('service_detection_dataset.csv', index=False)
print(f"[*] Saved {len(df)} samples to service_detection_dataset.csv")