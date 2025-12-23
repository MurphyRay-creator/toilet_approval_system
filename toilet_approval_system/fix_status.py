from app import app, db, ToiletRequest

with app.app_context():
    # 查找所有状态为'approve'的记录，改为'approved'
    approve_requests = ToiletRequest.query.filter_by(status='approve').all()
    for req in approve_requests:
        req.status = 'approved'
        print(f"Fixed request #{req.id}: approve -> approved")

    # 查找所有状态为'reject'的记录，改为'rejected'
    reject_requests = ToiletRequest.query.filter_by(status='reject').all()
    for req in reject_requests:
        req.status = 'rejected'
        print(f"Fixed request #{req.id}: reject -> rejected")

    db.session.commit()
    print("Database status values fixed!")