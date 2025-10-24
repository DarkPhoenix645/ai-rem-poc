#!/usr/bin/env python3
"""
Test script to demonstrate the compliance scraper and knowledge base population
"""

import asyncio
import subprocess
import sys
from pathlib import Path

async def main():
    """Run the complete pipeline: scrape -> populate"""
    
    print("🚀 Starting Compliance Knowledge Base Setup")
    print("=" * 50)
    
    # Step 1: Scrape compliance sources
    print("\n📥 Step 1: Scraping compliance sources...")
    try:
        result = subprocess.run([
            sys.executable, "scripts/scrape_compliance_sources.py"
        ], capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            print("✅ Scraping completed successfully")
            print(result.stdout)
        else:
            print("❌ Scraping failed:")
            print(result.stderr)
            return
    except subprocess.TimeoutExpired:
        print("⏰ Scraping timed out after 5 minutes")
        return
    except Exception as e:
        print(f"❌ Error running scraper: {e}")
        return
    
    # Step 2: Check what was scraped
    print("\n📁 Step 2: Checking scraped content...")
    data_dir = Path("data")
    if data_dir.exists():
        for cloud_dir in data_dir.iterdir():
            if cloud_dir.is_dir():
                print(f"\n📂 {cloud_dir.name}:")
                for service_dir in cloud_dir.iterdir():
                    if service_dir.is_dir():
                        md_files = list(service_dir.glob("*.md"))
                        print(f"  📄 {service_dir.name}: {len(md_files)} files")
                        for md_file in md_files[:3]:  # Show first 3 files
                            print(f"    - {md_file.name}")
                        if len(md_files) > 3:
                            print(f"    ... and {len(md_files) - 3} more")
    else:
        print("❌ No data directory found")
        return
    
    # Step 3: Populate knowledge base
    print("\n💾 Step 3: Populating knowledge base...")
    
    # Populate AWS data
    if (data_dir / "AWS").exists():
        print("  📊 Populating AWS knowledge base...")
        try:
            result = subprocess.run([
                sys.executable, "scripts/populate_knowledge_base.py", "data/AWS", "aws"
            ], capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                print("  ✅ AWS knowledge base populated")
                print(result.stdout)
            else:
                print("  ❌ AWS population failed:")
                print(result.stderr)
        except Exception as e:
            print(f"  ❌ Error populating AWS: {e}")
    
    # Populate TrendMicro data
    if (data_dir / "TrendMicro").exists():
        print("  📊 Populating TrendMicro knowledge base...")
        try:
            result = subprocess.run([
                sys.executable, "scripts/populate_knowledge_base.py", "data/TrendMicro", "trendmicro"
            ], capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                print("  ✅ TrendMicro knowledge base populated")
                print(result.stdout)
            else:
                print("  ❌ TrendMicro population failed:")
                print(result.stderr)
        except Exception as e:
            print(f"  ❌ Error populating TrendMicro: {e}")
    
    print("\n🎉 Knowledge base setup completed!")
    print("\nNext steps:")
    print("1. Start the application: ./scripts/run-app.sh")
    print("2. Start the worker: ./scripts/run-worker.sh")
    print("3. Test the API: curl http://localhost:8000/health")


if __name__ == "__main__":
    asyncio.run(main())
