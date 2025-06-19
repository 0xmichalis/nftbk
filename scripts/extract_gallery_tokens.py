import json
from typing import Dict, List
import requests
import os
import argparse


def parse_args():
    parser = argparse.ArgumentParser(description="Extract tokens from Gallery.so")
    parser.add_argument("--raw", action="store_true", help="Print raw response data and exit")
    return parser.parse_args()


args = parse_args()

gallery_id = os.getenv("GALLERY_ID")
if not gallery_id:
    raise ValueError("GALLERY_ID environment variable is not set.")
username = os.getenv("USERNAME")
if not username:
    raise ValueError("USERNAME environment variable is not set.")

url = "https://api.gallery.so/glry/graphql/query/GalleryIdFocusedGalleryQuery"

headers = {
    "Content-Type": "application/json",
}

payload = {
    "operationName": "GalleryIdFocusedGalleryQuery",
    "extensions": {
        "persistedQuery": {
            "version": 1,
            "sha256Hash": "d5065f9aeec8c1fd6945a7d8f71702e821f5b4d83fecff6cafbf169a24f9cd6f"
        }
    },
    "variables": {
        "galleryId": gallery_id,
        "username": username
    }
}

def hex_to_decimal(hex_str: str) -> str:
    """Convert hex token ID to decimal string"""
    hex_str = hex_str.replace('0x', '')
    return str(int(hex_str, 16))

def find_collection_tokens(obj: Dict) -> List[Dict]:
    """Recursively find all CollectionToken objects with their chain info"""
    tokens = []
    
    if isinstance(obj, dict):
        if obj.get('__typename') == 'CollectionToken':
            token_data = obj.get('token', {})
            definition = token_data.get('definition', {})
            contract = definition.get('contract', {}).get('contractAddress', {}).get('address')
            token_id = definition.get('tokenId')
            chain = definition.get('chain') or 'none'
            chain = chain.lower()
            
            if contract and token_id:
                tokens.append({
                    'contract': contract,
                    'token_id': token_id,
                    'chain': chain
                })
        
        for value in obj.values():
            if isinstance(value, (dict, list)):
                tokens.extend(find_collection_tokens(value))
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)):
                tokens.extend(find_collection_tokens(item))
    
    return tokens

def extract_tokens(data: Dict) -> Dict[str, List[str]]:
    """Extract and organize tokens by chain"""
    tokens = {
        "ethereum": [],
        "tezos": [],
        "zora": [],
        "base": [],
        "arbitrum": [],
        "none": []
    }
    
    collection_tokens = find_collection_tokens(data)
    for token in collection_tokens:
        token_id = hex_to_decimal(token['token_id'])
        chain = token['chain']
        
        if chain in tokens:
            tokens[chain].append(f"{token['contract']}:{token_id}")
        else:
            print(f"Warning: Unknown chain {chain}")
    
    return {k: sorted(v) for k, v in tokens.items() if v}

def generate_toml(tokens: Dict[str, List[str]]) -> str:
    """Generate TOML config output"""
    lines = []

    for chain, token_list in tokens.items():
        if token_list:
            lines.append(f"{chain} = [")
            for token in token_list:
                lines.append(f'    "{token}",')
            lines.append("]\n")
    
    return '\n'.join(lines)

if __name__ == "__main__":
    response = requests.post(url, json=payload, headers=headers)
    data = response.json()
    
    # Print raw response if --raw flag is set
    if args.raw:
        print(json.dumps(data, indent=2))
        exit(0)

    tokens = extract_tokens(data)
    print(generate_toml(tokens))
