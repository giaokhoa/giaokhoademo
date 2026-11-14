import type { ExecutionContext } from '@nestjs/common';
import type { Reflector } from '@nestjs/core';
import { describe, expect, it, vi } from 'vitest';
import type { SpaceDatabaseService } from '../db/routing/space-database.service';
import type { ContextsService } from '../modules/access/contexts.service';
import type { PermissionEvaluator } from '../modules/access/permission-evaluator.service';
import { CapabilityGuard } from './capability.guard';

function harness(spaceSlug?: string, allowed = true) {
  let insidePinnedSpace = false;
  const withSpaceKysely = vi.fn(async (_slug: string, fn: () => Promise<boolean>) => {
    insidePinnedSpace = true;
    try { return await fn(); }
    finally { insidePinnedSpace = false; }
  });
  const hasCapability = vi.fn(async () => {
    if (spaceSlug) expect(insidePinnedSpace).toBe(true);
    return allowed;
  });
  const reflector = {
    getAllAndOverride: vi.fn(() => ({ capability: 'role:assign', contextResolver: 'system' })),
  } as unknown as Reflector;
  const contexts = {
    ensureSystemContext: vi.fn(async () => ({ id: 'system-context' })),
  } as unknown as ContextsService;
  const evaluator = { hasCapability } as unknown as PermissionEvaluator;
  const spaceDb = { withSpaceKysely } as unknown as SpaceDatabaseService;
  const guard = new CapabilityGuard(reflector, evaluator, contexts, spaceDb);
  const request = {
    user: { id: 'centre-owner', username: 'manager' },
    tenantId: 'centre-tenant',
    spaceSlug,
    params: {},
    query: {},
  };
  const context = {
    getHandler: () => function handle() { return undefined; },
    getClass: () => class Handler {},
    switchToHttp: () => ({ getRequest: () => request }),
  } as unknown as ExecutionContext;
  return { guard, context, withSpaceKysely, hasCapability };
}

describe('CapabilityGuard request-space isolation', () => {
  it('checks role:assign in the centre database pinned by the preceding space guard', async () => {
    const { guard, context, withSpaceKysely, hasCapability } = harness('centre-a');
    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect(withSpaceKysely).toHaveBeenCalledWith('centre-a', expect.any(Function), {
      tenantId: 'centre-tenant', userId: 'centre-owner',
    });
    expect(hasCapability).toHaveBeenCalledWith('centre-owner', 'role:assign', 'system-context', {
      isGuest: false,
    });
  });

  it('does not route platform requests into a centre database', async () => {
    const { guard, context, withSpaceKysely } = harness();
    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect(withSpaceKysely).not.toHaveBeenCalled();
  });

  it('remains fail-closed when the dedicated scope lacks a capability', async () => {
    const { guard, context, withSpaceKysely } = harness('centre-a', false);
    await expect(guard.canActivate(context)).rejects.toMatchObject({
      status: 403,
      response: { code: 'access.capability_denied' },
    });
    expect(withSpaceKysely).toHaveBeenCalledTimes(1);
  });
});
