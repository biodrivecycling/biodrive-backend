import hashlib
from datetime import datetime
from flask import request, jsonify  # or FastAPI equivalent if you use that

def register_track_routes(app, db):
    """
    Call this once after your app and db are set up.
    Assumes Flask. Adjust slightly if you use FastAPI.
    """

    @app.route('/api/track', methods=['POST'])
    def track():
        try:
            data = request.get_json(silent=True) or {}
            path = str(data.get('path', '/'))[:500]

            # Daily rotating hash for approximate uniques (raw IP never stored)
            day_salt = datetime.utcnow().strftime('%Y-%m-%d')
            raw = (request.remote_addr or '') + (request.headers.get('User-Agent') or '') + day_salt
            visitor_hash = hashlib.sha256(raw.encode()).hexdigest()[:16]

            db.execute(
                "INSERT INTO site_page_views (path, visitor_hash) VALUES (%s, %s)",
                (path, visitor_hash)
            )
            db.commit()
        except Exception as e:
            # Never break the user experience
            print(f"[track] error: {e}")
        return '', 204

    @app.route('/api/admin/analytics', methods=['GET'])
    def analytics():
        # Protect this the same way you protect other admin routes
        # Example: check X-Admin-Key header
        admin_key = request.headers.get('X-Admin-Key')
        if admin_key != 'YOUR_EXISTING_ADMIN_KEY':  # replace with your real check
            return jsonify({'error': 'Unauthorized'}), 401

        try:
            days = min(max(int(request.args.get('days', 30)), 1), 365)

            summary = db.execute("""
                SELECT
                  COUNT(*)::int AS total_page_views,
                  COUNT(DISTINCT visitor_hash)::int AS approx_unique_visitors
                FROM site_page_views
                WHERE created_at > NOW() - (%s || ' days')::interval
            """, (days,)).fetchone()

            breakdown = db.execute("""
                SELECT
                  DATE_TRUNC('day', created_at) AS day,
                  path,
                  COUNT(*)::int AS page_views
                FROM site_page_views
                WHERE created_at > NOW() - (%s || ' days')::interval
                GROUP BY day, path
                ORDER BY day DESC, page_views DESC
                LIMIT 500
            """, (days,)).fetchall()

            return jsonify({
                'period_days': days,
                'summary': dict(summary) if summary else {},
                'breakdown': [dict(row) for row in breakdown]
            })
        except Exception as e:
            print(f"[analytics] error: {e}")
            return jsonify({'error': 'Failed to load analytics'}), 500
