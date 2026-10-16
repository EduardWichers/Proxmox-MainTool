# Software van anderen

## xterm.js (meegeleverd in `app/static/xterm/`)

De terminal in het consolevenster is xterm.js met de fit-add-on, ongewijzigd.

    Copyright (c) 2017-2019, The xterm.js authors (https://github.com/xtermjs/xterm.js)
    Copyright (c) 2014-2016, SourceLair Private Company (https://www.sourcelair.com)
    Copyright (c) 2012-2013, Christopher Jeffrey (https://github.com/chjj/)

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.

## Niet meegeleverd, wel gebruikt

- Tijdens het installeren haalt de container deze Python-pakketten op van PyPI, elk met zijn eigen licentie:
  FastAPI, Uvicorn (met websockets), proxmoxer en requests.
- Het zoekveld gebruikt de openbare catalogus van Proxmox VE Helper-Scripts (community-scripts.org). De tool
  toont alleen namen en omschrijvingen en verwijst door naar hun site; de scripts zelf zijn van hun makers.
- Proxmox is een merk van Proxmox Server Solutions GmbH. Deze tool is daar niet aan verbonden.
