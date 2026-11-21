import React from 'react';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { vi, describe, it, expect, beforeEach } from 'vitest';
import { InfrastructurePage } from '../pages/InfrastructurePage';
import { api } from '../api/client';
import { InfrastructureReadinessResponse } from '../types';

describe('InfrastructurePage Web Readiness View', () => {
  const mockInfrastructureData: InfrastructureReadinessResponse = {
    overall_status: 'APPLICATION_READY_DETONATION_BLOCKED',
    tiers: {
      APPLICATION_READY: true,
      STATIC_ANALYSIS_READY: true,
      AI_PROVIDER_READY: true,
      CAPE_API_READY: false,
      GUEST_READY: false,
      CONFINEMENT_VERIFIED: false,
      DETONATION_READY: false,
    },
    subsystems: {
      backend: {
        name: 'Malbox Backend & Database',
        tier: 'APPLICATION_READY',
        status: 'READY',
        details: 'FastAPI engine active; SQLite DB connected.',
        remediation: null,
      },
      ghidra: {
        name: 'Ghidra Headless Static Analysis',
        tier: 'STATIC_ANALYSIS_READY',
        status: 'READY',
        details: 'Ghidra analyzeHeadless ready for deep binary disassembly.',
        remediation: null,
      },
      cape: {
        name: 'CAPE Sandbox Controller API',
        tier: 'CAPE_API_READY',
        status: 'UNREACHABLE',
        details: 'Cannot communicate with CAPE API at http://127.0.0.1:8008.',
        remediation: './malbox setup --provision-cape',
      },
      guest: {
        name: 'Windows Analysis Guest VM',
        tier: 'GUEST_READY',
        status: 'UNAVAILABLE',
        details: 'No clean guest VMs available in CAPE.',
        remediation: './malbox setup --provision-guest',
      },
      isolation: {
        name: 'Network Isolation Confinement',
        tier: 'CONFINEMENT_VERIFIED',
        status: 'BLOCKED',
        details: 'Confinement attestation unverified; live malware execution is BLOCKED.',
        remediation: './malbox setup --attest-isolation --operator analyst --evidence-refs iptables:drop-rule --assert-all-invariants',
      },
      ai: {
        name: 'AI Intelligence Provider',
        tier: 'AI_PROVIDER_READY',
        status: 'READY',
        details: 'Deterministic rules-based local analyst engine.',
        remediation: null,
      },
      worker: {
        name: 'Pipeline Execution Worker',
        tier: 'APPLICATION_READY',
        status: 'READY',
        details: 'Single-worker concurrency lock active; safe recovery on restart.',
        remediation: null,
      },
      detonation: {
        name: 'Overall Detonation Readiness',
        tier: 'DETONATION_READY',
        status: 'BLOCKED',
        details: 'Live malware detonation is BLOCKED by security gate (fails closed).',
        remediation: './malbox setup --verify',
      },
    },
    remediation_commands: [
      './malbox setup --provision-cape',
      './malbox setup --provision-guest',
      './malbox setup --attest-isolation --operator analyst --evidence-refs iptables:drop-rule --assert-all-invariants',
      './malbox setup --verify',
    ],
    detonation_blockers: [
      'CAPE API unreachable at http://127.0.0.1:8008',
      'No guest analysis machines are registered or available',
      'CAPE network isolation attestation unverified',
    ],
    live_mode_enabled: true,
    default_backend: 'cape',
  };

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('renders overall readiness status and separates APPLICATION_READY from DETONATION_READY', async () => {
    vi.spyOn(api, 'getInfrastructureReadiness').mockResolvedValue(mockInfrastructureData);

    render(<InfrastructurePage />);

    expect(screen.getByText(/Checking platform infrastructure readiness tiers/i)).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText(/Infrastructure Setup & Readiness/i)).toBeInTheDocument();
    });

    // Check overall status badge
    expect(screen.getByText(/APPLICATION READY • DETONATION BLOCKED|APPLICATION READY DETONATION BLOCKED/i)).toBeInTheDocument();

    // Verify 7 core invariant tiers are displayed
    expect(screen.getByText('APPLICATION')).toBeInTheDocument();
    expect(screen.getByText('STATIC_ANALYSIS')).toBeInTheDocument();
    expect(screen.getByText('CAPE_API')).toBeInTheDocument();
    expect(screen.getByText('DETONATION')).toBeInTheDocument();

    // Verify subsystem cards
    expect(screen.getByText(/Malbox Backend & Database/i)).toBeInTheDocument();
    expect(screen.getByText(/CAPE Sandbox Controller API/i)).toBeInTheDocument();
    expect(screen.getByText(/Windows Analysis Guest VM/i)).toBeInTheDocument();
    expect(screen.getByText(/Network Isolation Confinement/i)).toBeInTheDocument();
  });

  it('displays copyable remediation CLI commands for blocked subsystems', async () => {
    vi.spyOn(api, 'getInfrastructureReadiness').mockResolvedValue(mockInfrastructureData);

    render(<InfrastructurePage />);

    await waitFor(() => {
      expect(screen.getByText(/.\/malbox setup --provision-cape/i)).toBeInTheDocument();
      expect(screen.getByText(/.\/malbox setup --provision-guest/i)).toBeInTheDocument();
    });

    // Verify copy button exists
    const copyButtons = screen.getAllByRole('button', { name: /Copy/i });
    expect(copyButtons.length).toBeGreaterThan(0);

    // Mock clipboard writeText
    const writeTextMock = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, {
      clipboard: {
        writeText: writeTextMock,
      },
    });

    fireEvent.click(copyButtons[0]);
    expect(writeTextMock).toHaveBeenCalled();
  });

  it('displays security notice prohibiting browser-based execution of privileged host commands', async () => {
    vi.spyOn(api, 'getInfrastructureReadiness').mockResolvedValue(mockInfrastructureData);

    render(<InfrastructurePage />);

    await waitFor(() => {
      expect(screen.getByText(/Security Invariant:/i)).toBeInTheDocument();
      expect(screen.getByText(/web sessions cannot execute arbitrary privileged installation commands/i)).toBeInTheDocument();
    });
  });
});
