# Trình quản lý tự động tải các plugin


from typing import Dict
from network_probe.core.context import ScanContext
from network_probe.core.engine import ScanEngine
from network_probe.plugins.reports.html_reporter import HtmlReporter
from network_probe.plugins.reports.json_reporter import JsonReporter
from network_probe.plugins.reports.normal_reporter import NormalReporter
from network_probe.plugins.reports.xml_reporter import XmlReporter


class ScanManagr():
    def __init__(self,context: ScanContext):

        self.context=context

        self.engine=ScanEngine(self.context)

    def run(self)-> Dict[str,any]:
        results=self.engine.run_scan()

        if not results:
            print(f"[Error] Không có kết quả nào được trả về")
            return {}
        self._generate_report(results)

        return results
    def _generate_report(self,results: Dict[str,any]):
        
        if self.context.output_html:
            HtmlReporter().save(results,self.context.output_html)
        elif self.context.output_json:
            JsonReporter().save(results,self.context.output_json)
        elif self.context.output_normal:
            NormalReporter().save(results,self.context.output_normal)
        elif self.context.output_xml:
            XmlReporter().save(results,self.context.output_xml)
            

        