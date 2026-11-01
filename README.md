# Aegis Guard Preview

This repository contains a standalone HTML preview of the Aegis Guard interface.

## What this preview does

The page lets you enter a host and view a mock scan plan in the browser. Its preview interaction runs locally in the page and sends no scan traffic.

## What this preview does not do

- It does not scan a website or IP address.
- It does not make DNS, TCP, TLS, or HTTP checks.
- It does not include the Python scanner or its server-side dashboard.
- It does not generate real security findings or reports.

Do not treat the mock plan as a security assessment or use it to make security decisions. The “Open the local dashboard” link works only if the separate Aegis Guard app is running on your own computer.

## View the page

Open [index.html](index.html) in a browser. To serve it as a website from this repository, enable GitHub Pages in the repository settings.

## Intro presentation

See [Aegis Guard Intro.pptx](Aegis%20Guard%20Intro.pptx) for the project introduction.
