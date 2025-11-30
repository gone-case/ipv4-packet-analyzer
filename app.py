import os
from flask import Flask, request, render_template, jsonify
from packet_parser import parse_pcap

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB

PARSED = {}    # store parsed packets

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    f = request.files.get('pcap')
    if not f:
        return jsonify({'error': 'no file uploaded'}), 400

    filename = f.filename
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    f.save(path)

    packets = parse_pcap(path)
    PARSED[filename] = packets

    return jsonify({'filename': filename, 'num_packets': len(packets)})

@app.route('/packets/<filename>')
def list_packets(filename):
    packets = PARSED.get(filename)
    if packets is None:
        return jsonify({'error': 'file not found'}), 404

    summary = [
        {
            'pkt_id': p['pkt_id'],
            'src': p['src_ip'],
            'dst': p['dst_ip'],
            'protocol': p['protocol'],
            'ttl': p['ttl'],
            'total_length': p['total_length']
        }
        for p in packets
    ]

    return jsonify(summary)

@app.route('/packet/<filename>/<int:pid>')
def get_packet(filename, pid):
    packets = PARSED.get(filename)
    if not packets:
        return jsonify({'error': 'file not found'}), 404

    for p in packets:
        if p['pkt_id'] == pid:
            return jsonify(p)

    return jsonify({'error': 'packet not found'}), 404

if __name__ == '__main__':
    app.run(debug=True)
