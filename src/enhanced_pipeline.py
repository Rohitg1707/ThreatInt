"""
Enhanced CTI Pipeline with ML and Analytics
"""

import asyncio
import logging
import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import os
from pathlib import Path

# Import existing modules
from .core.data_collector import DataCollector
from .core.threat_analyzer import ThreatAnalyzer
from .core.report_generator import ReportGenerator
from .ml.threat_classifier import ThreatClassifier
from .ml.anomaly_detector import AnomalyDetector
from .analytics.trend_analyzer import TrendAnalyzer
from .analytics.correlation_engine import CorrelationEngine

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EnhancedCTIPipeline:
    """Enhanced CTI Pipeline with ML capabilities and advanced analytics"""
    
    def __init__(self):
        """Initialize the enhanced pipeline"""
        self.data_collector = DataCollector()
        self.threat_analyzer = ThreatAnalyzer()
        self.report_generator = ReportGenerator()
        
        # ML components
        self.threat_classifier = ThreatClassifier()
        self.anomaly_detector = AnomalyDetector()
        
        # Analytics components  
        self.trend_analyzer = TrendAnalyzer()
        self.correlation_engine = CorrelationEngine()
        
        # Pipeline state
        self.pipeline_start_time = None
        self.collected_data = []
        self.analysis_results = {}
        self.ml_results = {}
        self.analytics_results = {}
        
    async def run_enhanced_pipeline(self, config: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Run the complete enhanced CTI pipeline
        
        Args:
            config: Optional configuration dictionary
            
        Returns:
            Dict containing all pipeline results
        """
        self.pipeline_start_time = datetime.now()
        logger.info("Starting Enhanced CTI Pipeline...")
        
        try:
            # Step 1: Data Collection
            logger.info("Step 1: Collecting threat intelligence data...")
            self.collected_data = await self._collect_data(config)
            
            # Step 2: Traditional Threat Analysis
            logger.info("Step 2: Performing traditional threat analysis...")
            self.analysis_results = await self._analyze_threats()
            
            # Step 3: ML-based Analysis
            logger.info("Step 3: Running ML-based analysis...")
            self.ml_results = await self._run_ml_analysis()
            
            # Step 4: Advanced Analytics
            logger.info("Step 4: Performing advanced analytics...")
            self.analytics_results = await self._run_analytics()
            
            # Step 5: Generate Enhanced Report
            logger.info("Step 5: Generating enhanced report...")
            report = await self._generate_enhanced_report()
            
            # Step 6: Save Results
            logger.info("Step 6: Saving results...")
            await self._save_results(report)
            
            pipeline_duration = datetime.now() - self.pipeline_start_time
            logger.info(f"Enhanced CTI Pipeline completed in {pipeline_duration}")
            
            return {
                'status': 'success',
                'duration': str(pipeline_duration),
                'data_collected': len(self.collected_data),
                'analysis_results': self.analysis_results,
                'ml_results': self.ml_results,
                'analytics_results': self.analytics_results,
                'report': report
            }
            
        except Exception as e:
            logger.error(f"Enhanced CTI Pipeline failed: {str(e)}")
            return {
                'status': 'error',
                'error': str(e),
                'duration': str(datetime.now() - self.pipeline_start_time) if self.pipeline_start_time else None
            }
    
    async def _collect_data(self, config: Optional[Dict] = None) -> List[Dict]:
        """Collect threat intelligence data from various sources"""
        try:
            # Use existing data collector
            feeds = [
                'https://feodotracker.abuse.ch/downloads/ipblocklist.csv',
                'https://sslbl.abuse.ch/blacklist/sslipblacklist.csv'
            ]
            
            all_data = []
            for feed in feeds:
                try:
                    data = await self.data_collector.collect_from_feed(feed)
                    all_data.extend(data)
                except Exception as e:
                    logger.warning(f"Failed to collect from {feed}: {str(e)}")
            
            logger.info(f"Collected {len(all_data)} threat indicators")
            return all_data
            
        except Exception as e:
            logger.error(f"Data collection failed: {str(e)}")
            return []
    
    async def _analyze_threats(self) -> Dict[str, Any]:
        """Perform traditional threat analysis"""
        try:
            if not self.collected_data:
                return {'status': 'no_data', 'threats': []}
            
            # Use existing threat analyzer
            analysis_results = []
            for data_item in self.collected_data[:100]:  # Limit for demo
                try:
                    result = await self.threat_analyzer.analyze_indicator(data_item)
                    analysis_results.append(result)
                except Exception as e:
                    logger.warning(f"Failed to analyze indicator: {str(e)}")
            
            # Aggregate results
            threat_types = {}
            severity_counts = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
            
            for result in analysis_results:
                # Count threat types
                threat_type = result.get('type', 'unknown')
                threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
                
                # Count severity levels
                severity = result.get('severity', 'low')
                if severity in severity_counts:
                    severity_counts[severity] += 1
            
            return {
                'status': 'success',
                'total_analyzed': len(analysis_results),
                'threat_types': threat_types,
                'severity_distribution': severity_counts,
                'high_priority_threats': [r for r in analysis_results if r.get('severity') in ['high', 'critical']]
            }
            
        except Exception as e:
            logger.error(f"Threat analysis failed: {str(e)}")
            return {'status': 'error', 'error': str(e)}
    
    async def _run_ml_analysis(self) -> Dict[str, Any]:
        """Run ML-based analysis on collected data"""
        try:
            if not self.collected_data:
                return {'status': 'no_data'}
            
            ml_results = {}
            
            # Threat Classification
            try:
                logger.info("Running threat classification...")
                classification_results = await self.threat_classifier.classify_batch(self.collected_data[:50])
                ml_results['classification'] = {
                    'status': 'success',
                    'results': classification_results,
                    'summary': self._summarize_classifications(classification_results)
                }
            except Exception as e:
                logger.warning(f"Threat classification failed: {str(e)}")
                ml_results['classification'] = {'status': 'error', 'error': str(e)}
            
            # Anomaly Detection
            try:
                logger.info("Running anomaly detection...")
                anomaly_results = await self.anomaly_detector.detect_batch(self.collected_data[:50])
                ml_results['anomaly_detection'] = {
                    'status': 'success',
                    'results': anomaly_results,
                    'anomaly_count': len([r for r in anomaly_results if r.get('is_anomaly', False)])
                }
            except Exception as e:
                logger.warning(f"Anomaly detection failed: {str(e)}")
                ml_results['anomaly_detection'] = {'status': 'error', 'error': str(e)}
            
            return ml_results
            
        except Exception as e:
            logger.error(f"ML analysis failed: {str(e)}")
            return {'status': 'error', 'error': str(e)}
    
    async def _run_analytics(self) -> Dict[str, Any]:
        """Run advanced analytics on collected data"""
        try:
            analytics_results = {}
            
            # Trend Analysis
            try:
                logger.info("Running trend analysis...")
                trend_results = await self.trend_analyzer.analyze_trends(self.collected_data)
                analytics_results['trends'] = trend_results
            except Exception as e:
                logger.warning(f"Trend analysis failed: {str(e)}")
                analytics_results['trends'] = {'status': 'error', 'error': str(e)}
            
            # Correlation Analysis
            try:
                logger.info("Running correlation analysis...")
                correlation_results = await self.correlation_engine.find_correlations(self.collected_data)
                analytics_results['correlations'] = correlation_results
            except Exception as e:
                logger.warning(f"Correlation analysis failed: {str(e)}")
                analytics_results['correlations'] = {'status': 'error', 'error': str(e)}
            
            return analytics_results
            
        except Exception as e:
            logger.error(f"Analytics failed: {str(e)}")
            return {'status': 'error', 'error': str(e)}
    
    async def _generate_enhanced_report(self) -> Dict[str, Any]:
        """Generate enhanced report with all analysis results"""
        try:
            # Create comprehensive report
            report = {
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'pipeline_duration': str(datetime.now() - self.pipeline_start_time),
                    'data_sources_count': len(self.collected_data),
                    'version': '2.0'
                },
                'executive_summary': self._create_executive_summary(),
                'traditional_analysis': self.analysis_results,
                'ml_analysis': self.ml_results,
                'advanced_analytics': self.analytics_results,
                'recommendations': self._generate_recommendations()
            }
            
            # Use existing report generator for formatting
            formatted_report = await self.report_generator.generate_report(report)
            
            return formatted_report
            
        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}")
            return {'status': 'error', 'error': str(e)}
    
    def _create_executive_summary(self) -> Dict[str, Any]:
        """Create executive summary of all findings"""
        try:
            total_indicators = len(self.collected_data)
            high_priority_count = len(self.analysis_results.get('high_priority_threats', []))
            anomaly_count = self.ml_results.get('anomaly_detection', {}).get('anomaly_count', 0)
            
            risk_level = 'low'
            if high_priority_count > 10 or anomaly_count > 5:
                risk_level = 'high'
            elif high_priority_count > 5 or anomaly_count > 2:
                risk_level = 'medium'
            
            return {
                'overall_risk_level': risk_level,
                'total_indicators_analyzed': total_indicators,
                'high_priority_threats': high_priority_count,
                'anomalies_detected': anomaly_count,
                'key_findings': self._extract_key_findings()
            }
        except Exception as e:
            logger.error(f"Executive summary creation failed: {str(e)}")
            return {'error': str(e)}
    
    def _extract_key_findings(self) -> List[str]:
        """Extract key findings from all analyses"""
        findings = []
        
        # From traditional analysis
        if self.analysis_results.get('threat_types'):
            top_threat = max(self.analysis_results['threat_types'].items(), key=lambda x: x[1])
            findings.append(f"Most common threat type: {top_threat[0]} ({top_threat[1]} instances)")
        
        # From ML analysis
        if self.ml_results.get('anomaly_detection', {}).get('anomaly_count', 0) > 0:
            findings.append(f"Detected {self.ml_results['anomaly_detection']['anomaly_count']} anomalous patterns")
        
        # From analytics
        if self.analytics_results.get('trends', {}).get('status') == 'success':
            findings.append("Trend analysis completed - check detailed results")
        
        return findings
    
    def _generate_recommendations(self) -> List[str]:
        """Generate actionable recommendations based on findings"""
        recommendations = []
        
        # Based on high priority threats
        high_priority_count = len(self.analysis_results.get('high_priority_threats', []))
        if high_priority_count > 5:
            recommendations.append("Consider implementing additional monitoring for high-priority threats")
        
        # Based on anomalies
        anomaly_count = self.ml_results.get('anomaly_detection', {}).get('anomaly_count', 0)
        if anomaly_count > 3:
            recommendations.append("Investigate anomalous patterns detected by ML analysis")
        
        # General recommendations
        recommendations.extend([
            "Maintain regular threat intelligence feed updates",
            "Review and update detection rules based on latest threat patterns",
            "Consider threat hunting activities based on correlation findings"
        ])
        
        return recommendations
    
    def _summarize_classifications(self, classifications: List[Dict]) -> Dict[str, int]:
        """Summarize classification results"""
        summary = {}
        for classification in classifications:
            class_type = classification.get('predicted_class', 'unknown')
            summary[class_type] = summary.get(class_type, 0) + 1
        return summary
    
    async def _save_results(self, report: Dict[str, Any]) -> None:
        """Save pipeline results to files"""
        try:
            # Create reports directory if it doesn't exist
            reports_dir = Path('reports')
            reports_dir.mkdir(exist_ok=True)
            
            # Save main report
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_file = reports_dir / f'enhanced_cti_report_{timestamp}.json'
            
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            logger.info(f"Enhanced report saved to {report_file}")
            
        except Exception as e:
            logger.error(f"Failed to save results: {str(e)}")

# Main function that can be imported
async def run_enhanced_pipeline_main():
    """
    Main function to run the enhanced CTI pipeline
    This is the function that gets called from __main__.py
    """
    pipeline = EnhancedCTIPipeline()
    results = await pipeline.run_enhanced_pipeline()
    
    print(f"\nEnhanced CTI Pipeline Results:")
    print(f"Status: {results['status']}")
    print(f"Duration: {results.get('duration', 'N/A')}")
    
    if results['status'] == 'success':
        print(f"Data collected: {results.get('data_collected', 0)} indicators")
        print(f"Analysis completed with ML and advanced analytics")
        print(f"Report generated successfully")
    else:
        print(f"Error: {results.get('error', 'Unknown error')}")
    
    return results

# Alternative sync wrapper for compatibility
def run_enhanced_pipeline_sync():
    """Synchronous wrapper for the enhanced pipeline"""
    return asyncio.run(run_enhanced_pipeline_main())