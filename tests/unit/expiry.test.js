import { describe, expect, it } from 'vitest';
import {
  dateInputToExpiresAt,
  defaultExpiresAtDateInput,
  defaultExpiresAtOneYear,
  getDaysRemaining,
  getExpiryStyleClass,
  isExpired,
  toDateInputValue
} from '../../src/utils/expiry.js';
import {
  isExpired as isExpiredFn,
  persistExpiryDisables,
  shouldSkipExpiredManualNode
} from '../../functions/utils/expiry.js';

describe('expiry utils (frontend)', () => {
  it('空值与非法日期视为未过期', () => {
    expect(isExpired('')).toBe(false);
    expect(isExpired(null)).toBe(false);
    expect(isExpired(undefined)).toBe(false);
    expect(isExpired('not-a-date')).toBe(false);
  });

  it('过去时间过期，未来时间不过期', () => {
    const now = new Date('2026-07-23T12:00:00.000Z');
    expect(isExpired('2026-07-22T23:59:59.999Z', now)).toBe(true);
    expect(isExpired('2026-07-24T00:00:00.000Z', now)).toBe(false);
  });

  it('默认一年为约 365 天后的日末 ISO', () => {
    const from = new Date('2026-01-15T08:00:00.000Z');
    const iso = defaultExpiresAtOneYear(from);
    const parsed = new Date(iso);
    expect(parsed.getFullYear()).toBe(2027);
    expect(toDateInputValue(iso)).toBe(defaultExpiresAtDateInput(from));
  });

  it('date input 转为日末 ISO', () => {
    const iso = dateInputToExpiresAt('2027-01-15');
    expect(iso).toBeTruthy();
    const date = new Date(iso);
    expect(Number.isNaN(date.getTime())).toBe(false);
    expect(date.getHours()).toBe(23);
    expect(date.getMinutes()).toBe(59);
  });
  it('getDaysRemaining 按日计算，临期样式在 30 天内为红', () => {
    const now = new Date('2026-07-23T12:00:00');
    expect(getDaysRemaining('2026-08-01T23:59:59', now)).toBe(9);
    expect(getExpiryStyleClass(9)).toContain('text-red-500');
    expect(getExpiryStyleClass(31)).toContain('text-gray-500');
    expect(getExpiryStyleClass(-1)).toContain('text-red-500');
    expect(getDaysRemaining('', now)).toBeNull();
  });
});

describe('expiry utils (functions)', () => {
  it('shouldSkipExpiredManualNode 只针对过期手动节点', () => {
    const now = new Date('2026-07-23T12:00:00.000Z');
    expect(shouldSkipExpiredManualNode({
      url: 'hysteria2://x@1.2.3.4:443',
      expiresAt: '2026-01-01T00:00:00.000Z'
    }, now)).toBe(true);
    expect(shouldSkipExpiredManualNode({
      url: 'hysteria2://x@1.2.3.4:443',
      expiresAt: '2027-01-01T00:00:00.000Z'
    }, now)).toBe(false);
    expect(shouldSkipExpiredManualNode({
      url: 'https://example.com/sub',
      expiresAt: '2026-01-01T00:00:00.000Z'
    }, now)).toBe(false);
    expect(shouldSkipExpiredManualNode({
      url: 'ss://abc@1.2.3.4:8388'
    }, now)).toBe(false);
  });

  it('persistExpiryDisables 将目标项 enabled 置为 false', async () => {
    let savedSubs = null;
    let savedProfiles = null;
    const storage = {
      async getAllSubscriptions() {
        return [
          { id: 'n1', enabled: true, url: 'ss://a' },
          { id: 'n2', enabled: true, url: 'ss://b' }
        ];
      },
      async putAllSubscriptions(items) {
        savedSubs = items;
      },
      async getAllProfiles() {
        return [
          { id: 'p1', enabled: true, expiresAt: '2020-01-01' },
          { id: 'p2', enabled: true }
        ];
      },
      async putAllProfiles(items) {
        savedProfiles = items;
      }
    };

    await persistExpiryDisables(storage, {
      subscriptionIds: ['n1'],
      profileIds: ['p1']
    });

    expect(savedSubs.find(s => s.id === 'n1').enabled).toBe(false);
    expect(savedSubs.find(s => s.id === 'n2').enabled).toBe(true);
    expect(savedProfiles.find(p => p.id === 'p1').enabled).toBe(false);
    expect(savedProfiles.find(p => p.id === 'p2').enabled).toBe(true);
    expect(isExpiredFn('2020-01-01')).toBe(true);
  });
});
