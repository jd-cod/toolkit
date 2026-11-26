/**
 * Cloudflare R2 Storage Client
 *
 * S3-compatible object storage for nginx logs and shares.
 * Features:
 *  - Direct presigned uploads (bypass server bandwidth)
 *  - Presigned downloads (1-hour expiry)
 *  - Automatic cleanup of expired objects
 *  - Ephemeral session support (10-min TTL)
 */

import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand, ListObjectsV2Command, HeadObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import crypto from 'crypto';

class R2StorageClient {
  constructor() {
    this.accountId = process.env.R2_ACCOUNT_ID;
    this.accessKeyId = process.env.R2_ACCESS_KEY_ID;
    this.secretAccessKey = process.env.R2_SECRET_ACCESS_KEY;
    this.bucketName = process.env.R2_BUCKET_NAME || 'systoolkit-logs';

    if (!this.accountId || !this.accessKeyId || !this.secretAccessKey) {
      console.warn('⚠️  R2 credentials not configured. Storage features will be unavailable.');
      this.enabled = false;
      return;
    }

    this.enabled = true;

    // Initialize S3-compatible client for R2
    this.client = new S3Client({
      region: 'auto',
      endpoint: `https://${this.accountId}.r2.cloudflarestorage.com`,
      credentials: {
        accessKeyId: this.accessKeyId,
        secretAccessKey: this.secretAccessKey,
      },
    });

    console.log(`✅ R2 Storage initialized: ${this.bucketName}`);
  }

  /**
   * Check if R2 is properly configured
   */
  isEnabled() {
    return this.enabled;
  }

  /**
   * Generate a unique share code (8 characters)
   */
  generateShareCode() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const bytes = crypto.randomBytes(8);
    return Array.from(bytes, b => chars[b % chars.length]).join('');
  }

  /**
   * Upload log file to R2
   * @param {string} key - Object key (e.g., "shares/abc123.log.gz" or "ephemeral/xyz789.log.gz")
   * @param {Buffer} buffer - File content (should be gzipped)
   * @param {Object} metadata - Custom metadata to attach
   * @returns {Promise<Object>} Upload result
   */
  async uploadLog(key, buffer, metadata = {}) {
    if (!this.enabled) {
      throw new Error('R2 storage is not configured');
    }

    const command = new PutObjectCommand({
      Bucket: this.bucketName,
      Key: key,
      Body: buffer,
      ContentType: 'application/gzip',
      ContentEncoding: 'gzip',
      Metadata: {
        ...metadata,
        'uploaded-at': new Date().toISOString(),
      },
    });

    await this.client.send(command);

    return {
      success: true,
      key,
      size: buffer.length,
      bucket: this.bucketName,
    };
  }

  /**
   * Upload metadata JSON file to R2
   * @param {string} key - Object key (e.g., "shares/abc123.metadata.json")
   * @param {Object} metadata - Metadata object to store
   */
  async uploadMetadata(key, metadata) {
    if (!this.enabled) {
      throw new Error('R2 storage is not configured');
    }

    const command = new PutObjectCommand({
      Bucket: this.bucketName,
      Key: key,
      Body: JSON.stringify(metadata),
      ContentType: 'application/json',
    });

    await this.client.send(command);
  }

  /**
   * Generate presigned URL for UPLOADING to R2 (client uploads directly to R2)
   * @param {string} key - Object key
   * @param {number} expiresIn - URL expiry in seconds (default: 15 minutes)
   * @returns {Promise<string>} Presigned upload URL
   */
  async generatePresignedUploadUrl(key, expiresIn = 900) {
    if (!this.enabled) {
      throw new Error('R2 storage is not configured');
    }

    const command = new PutObjectCommand({
      Bucket: this.bucketName,
      Key: key,
      ContentType: 'application/gzip',
    });

    return getSignedUrl(this.client, command, { expiresIn });
  }

  /**
   * Head object to check existence and size
   * @param {string} key - Object key
   * @returns {Promise<{ size: number, metadata: Object } | null>}
   */
  async headObject(key) {
    if (!this.enabled) {
      throw new Error('R2 storage is not configured');
    }

    try {
      const command = new HeadObjectCommand({
        Bucket: this.bucketName,
        Key: key,
      });

      const response = await this.client.send(command);
      return {
        size: response.ContentLength || 0,
        metadata: response.Metadata || {},
      };
    } catch (err) {
      if (err.name === 'NotFound' || err.$metadata?.httpStatusCode === 404) {
        return null;
      }
      throw err;
    }
  }

  /**
   * Generate presigned URL for DOWNLOADING from R2 (client downloads directly from R2)
   * @param {string} key - Object key
   * @param {number} expiresIn - URL expiry in seconds (default: 1 hour)
   * @returns {Promise<string>} Presigned download URL
   */
  async generatePresignedDownloadUrl(key, expiresIn = 3600) {
    if (!this.enabled) {
      throw new Error('R2 storage is not configured');
    }

    const command = new GetObjectCommand({
      Bucket: this.bucketName,
      Key: key,
    });

    const url = await getSignedUrl(this.client, command, { expiresIn });
    return url;
  }

  /**
   * Get metadata for an object
   * @param {string} key - Object key
   * @returns {Promise<Object>} Object metadata
   */
  async getMetadata(key) {
    if (!this.enabled) {
      throw new Error('R2 storage is not configured');
    }

    const command = new HeadObjectCommand({
      Bucket: this.bucketName,
      Key: key,
    });

    const response = await this.client.send(command);
    return {
      size: response.ContentLength,
      lastModified: response.LastModified,
      contentType: response.ContentType,
      metadata: response.Metadata || {},
    };
  }

  /**
   * Delete object from R2
   * @param {string} key - Object key
   */
  async deleteLog(key) {
    if (!this.enabled) {
      throw new Error('R2 storage is not configured');
    }

    const command = new DeleteObjectCommand({
      Bucket: this.bucketName,
      Key: key,
    });

    await this.client.send(command);
  }

  /**
   * List objects with a given prefix
   * @param {string} prefix - Object key prefix (e.g., "ephemeral/", "shares/")
   * @param {number} maxKeys - Maximum number of keys to return
   * @returns {Promise<Array>} List of objects
   */
  async listObjects(prefix, maxKeys = 1000) {
    if (!this.enabled) {
      throw new Error('R2 storage is not configured');
    }

    const command = new ListObjectsV2Command({
      Bucket: this.bucketName,
      Prefix: prefix,
      MaxKeys: maxKeys,
    });

    const response = await this.client.send(command);
    return response.Contents || [];
  }

  /**
   * Delete multiple objects by their keys
   * @param {Array<string>} keys - Array of object keys to delete
   */
  async deleteMultiple(keys) {
    if (!this.enabled) {
      throw new Error('R2 storage is not configured');
    }

    if (keys.length === 0) return;

    // R2 supports batch delete, but for simplicity we'll delete one by one
    // Can be optimized with DeleteObjectsCommand later if needed
    const deletePromises = keys.map(key => this.deleteLog(key));
    await Promise.all(deletePromises);
  }

  /**
   * Cleanup expired ephemeral sessions
   * @param {Date} cutoffDate - Delete sessions older than this date
   * @returns {Promise<number>} Number of deleted objects
   */
  async cleanupEphemeral(cutoffDate) {
    if (!this.enabled) {
      return 0;
    }

    try {
      const objects = await this.listObjects('ephemeral/');
      const toDelete = objects.filter(obj => obj.LastModified < cutoffDate);

      if (toDelete.length > 0) {
        await this.deleteMultiple(toDelete.map(obj => obj.Key));
        console.log(`🧹 Cleaned up ${toDelete.length} expired ephemeral sessions from R2`);
      }

      return toDelete.length;
    } catch (err) {
      console.error('Error cleaning up ephemeral R2 objects:', err);
      return 0;
    }
  }

  /**
   * Cleanup expired shares (past grace period)
   * @param {Date} cutoffDate - Delete shares with expires_at before this date
   * @param {Array<string>} r2Keys - Array of r2_key values from database
   * @returns {Promise<number>} Number of deleted objects
   */
  async cleanupExpiredShares(r2Keys) {
    if (!this.enabled || !r2Keys || r2Keys.length === 0) {
      return 0;
    }

    try {
      const keysToDelete = [];

      // Delete both .log.gz and .metadata.json files
      for (const r2Key of r2Keys) {
        keysToDelete.push(r2Key);
        keysToDelete.push(`${r2Key}.metadata.json`);
      }

      await this.deleteMultiple(keysToDelete);
      console.log(`🧹 Cleaned up ${r2Keys.length} expired shares from R2 (${keysToDelete.length} objects total)`);

      return r2Keys.length;
    } catch (err) {
      console.error('Error cleaning up expired shares from R2:', err);
      return 0;
    }
  }
}

// Export singleton instance
const r2Storage = new R2StorageClient();
export default r2Storage;
