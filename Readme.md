# 5G Fake Base Station Implementation



## Deadlines

- [ ] 04/01 Mini-report #4 (Sprint 4) 
  - [ ] Get simulated gNB & UE working.
  - [ ] Perform successful handover. 
  - [ ] Identify Attack surface for OTA implementation.
- [ ] 04/20 Mid-stage
  - [ ] Derive Defense strategy.
- [ ] 04/29 Mini-report #5 (Sprint 5)
- [ ] 05/11 Final report + code due

## NGAP PCAP GUI (gNB Broadcaster)

Run the gNB GUI from the workspace root:

```bash
python -m fake_base_station.gui
```

Alternative launch (also from workspace root):

```bash
python src/fake_base_station/gui.py
```

### GUI Workflow

1. **Load PCAP**: Browse and select a `.pcap` file
2. **View Packets**: A table shows all packets with:
   - Index, Protocol (SCTP/UDP), Source/Dest IP & ports
   - Payload size, NGAP indicator (green rows = NGAP packets)
3. **Select Packets**: Click rows to select; use **Select All** / **Clear** buttons
4. **Set Destination IP**: Enter the new destination IP for selected packets
5. **Modify Release Signal**: Mark/clear/toggle release flags on selected packets
6. **Replay**: Configure replay host/port/protocol, then click **Replay Selected**
7. **Monitor**: Watch the log panel for progress and errors

**Note**: Modifications apply in-memory during replay—no temp files are created.

## NGAP UE Listener GUI

Run the UE Listener GUI from the workspace root:

```bash
python -m fake_base_station.ue_gui
```

Alternative launch (also from workspace root):

```bash
python src/fake_base_station/ue_gui.py
```

### UE Listener Workflow

1. **Configure Interface**: Enter a network interface name (e.g., `eth0`, or leave empty for all interfaces)
2. **Start Listening**: Click **Start Listening** to begin capturing packets
3. **Monitor Packets**: Live table shows all captured packets with:
   - Timestamp, Source/Dest IP & ports
   - Protocol (SCTP/UDP), Payload size
   - NGAP indicator, Release signal status
4. **Filter Packets**: Similar to gNB GUI—filter by IP, port, protocol, NGAP flag
   - **Default filter**: NGAP packets only (focus on NGAP traffic)
5. **Apply Filters**: Click **Apply Filter** to update the display
6. **Clear Data**: Click **Clear All Packets** to reset captured traffic
7. **Stop Listening**: Click **Stop Listening** to end capture

The listener automatically detects SCTP data chunks and NGAP payloads, showing the same Release signal detection as the gNB GUI.
