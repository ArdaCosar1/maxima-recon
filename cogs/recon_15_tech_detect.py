#!/usr/bin/env python3
"""
Maxima Cog: Technology Detector
Module: TechnologyDetector
"""
import sys
import os
from utils.base_module import BaseModule, ModuleResult


class TechnologyDetector(BaseModule):
    """Technology Detector"""

    FINGERPRINTS = {
        "WordPress":   ["wp-content","wp-json","wordpress"],
        "Drupal":      ["drupal.js","Drupal.settings","sites/default"],
        "Joomla":      ["joomla","option=com_"],
        "Laravel":     ["laravel_session","Laravel"],
        "Django":      ["csrfmiddlewaretoken","django"],
        "React":       ["__reactFiber","react.js","reactDOM"],
        "Angular":     ["ng-version","angular.js"],
        "Vue.js":      ["__vue__","vue.min.js"],
        "jQuery":      ["jquery.min.js","jQuery v"],
        "Bootstrap":   ["bootstrap.min.css","bootstrap.js"],
        "Nginx":       ["nginx"],
        "Apache":      ["apache"],
    }
    def run(self) -> ModuleResult:
        self.log("Teknoloji tespiti...")
        resp = self.http_get(self.url)
        body = resp.get("body","").lower()
        headers_str = str(resp.get("headers",{})).lower()
        detected = []
        for tech, signs in self.FINGERPRINTS.items():
            for sign in signs:
                if sign.lower() in body or sign.lower() in headers_str:
                    detected.append(tech)
                    self.add_finding(f"Teknoloji: {tech}", f"İmza: {sign}", "info")
                    break
        self.results["summary"]["Tespit Edilen"] = ", ".join(detected) or "Bilinmiyor"
        return self.results

