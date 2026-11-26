'use client';
import { useState } from 'react';
import { adminApi, errorMessage } from './adminUtils';
import { useToast } from './AdminToast';

export default function ChangePasswordSection() {
  const { toast } = useToast();
  const [current, setCurrent] = useState('');
  const [newPw, setNewPw] = useState('');
  const [confirm, setConfirm] = useState('');
  const [saving, setSaving] = useState(false);

  async function handleSubmit() {
    if (!current || !newPw || !confirm) {
      toast('All fields are required', 'error');
      return;
    }
    if (newPw !== confirm) {
      toast('New passwords do not match', 'error');
      return;
    }
    if (newPw.length < 12) {
      toast('New password must be at least 12 characters', 'error');
      return;
    }

    setSaving(true);
    try {
      await adminApi('/password', {
        method: 'PUT',
        body: { current_password: current, new_password: newPw },
      });
      toast('Password changed successfully!');
      setCurrent('');
      setNewPw('');
      setConfirm('');
    } catch (e) {
      toast('Failed to change password: ' + errorMessage(e), 'error');
    }
    setSaving(false);
  }

  return (
    <div className="admin-card" style={{ maxWidth: 500 }}>
      <div className="admin-card-header">
        <h3 className="admin-card-title">Change Password</h3>
      </div>
      <div className="admin-card-body">
        <div className="form-group">
          <label className="form-label">Current Password</label>
          <input
            className="form-input"
            type="password"
            value={current}
            onChange={e => setCurrent(e.target.value)}
            placeholder="Enter current password"
          />
        </div>
        <div className="form-group">
          <label className="form-label">New Password</label>
          <input
            className="form-input"
            type="password"
            value={newPw}
            onChange={e => setNewPw(e.target.value)}
            placeholder="Enter new password (min 12 chars)"
          />
        </div>
        <div className="form-group">
          <label className="form-label">Confirm New Password</label>
          <input
            className="form-input"
            type="password"
            value={confirm}
            onChange={e => setConfirm(e.target.value)}
            placeholder="Re-enter new password"
          />
        </div>
        <button
          className="btn btn-sm btn-admin-primary"
          onClick={handleSubmit}
          disabled={saving}
        >
          <i className={`bi ${saving ? 'bi-hourglass-split' : 'bi-key-fill'}`} />{' '}
          {saving ? 'Updating...' : 'Update Password'}
        </button>
      </div>
    </div>
  );
}
