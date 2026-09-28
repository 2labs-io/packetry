===============================
Capturing from the Command Line
===============================

``packetry-capture`` captures from an attached analyzer straight to a PcapNG file, without opening the Packetry window. Use it to script captures, or to capture on a machine without a display. Open the file in Packetry afterwards to analyze it.

Capture at High Speed until you press Ctrl-C:

.. code::

   packetry-capture capture.pcapng

Capture for five seconds at Full Speed, with a comment stored in the file:

.. code::

   packetry-capture --speed full --duration 5 --comment "keyboard plugged in" capture.pcapng

The capture also stops on SIGTERM, so a script can run ``packetry-capture`` in the background and stop it with ``kill``. Packets are written to the file as they arrive, and an existing file is never overwritten.

Power Control
-------------

On analyzers that support power control, the same settings as in the Packetry window are available. To capture a device being powered on, turn target power off, then have it turned on when capture starts:

.. code::

   packetry-capture --power-source TARGET-C --power off --power-on-start capture.pcapng

Exit Status
-----------

``packetry-capture`` exits with status 0 when the capture is complete, 1 on an error, and 2 if the analyzer's buffer overflowed during the capture, in which case packets are missing from the file.

Run ``packetry-capture --help`` for all options, and ``packetry-capture --list`` to see attached analyzers.
