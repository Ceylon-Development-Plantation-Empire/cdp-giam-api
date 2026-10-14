<?php

namespace App\Services\Security;

use InvalidArgumentException;

/**
 * Enterprise SSRF and URL security validator enforcing network boundary controls,
 * cloud metadata protection, and protocol constraints.
 */
class UrlSecurityValidator
{
    /**
     * Forbidden cloud metadata IP addresses and hostnames.
     */
    protected const CLOUD_METADATA_HOSTS = [
        '169.254.169.254',
        'metadata.google.internal',
        'metadata.goog',
        '100.100.100.200',
        'fd00:ec2::254',
    ];

    /**
     * Determine if a URL is valid and safe against SSRF constraints.
     */
    public function isValid(string $url, bool $enforceHttps = false): bool
    {
        return $this->validate($url, $enforceHttps)['valid'];
    }

    /**
     * Validate an integration endpoint or redirect URI against SSRF and network risks.
     *
     * @param string $url The target URL to inspect.
     * @param bool $enforceHttps In production, require https protocol.
     * @return array{valid: bool, error: ?string}
     */
    public function validate(string $url, bool $enforceHttps = false): array
    {
        $parts = parse_url($url);

        if ($parts === false || empty($parts['scheme']) || empty($parts['host'])) {
            return ['valid' => false, 'error' => 'Malformed URL: missing scheme or host.'];
        }

        $scheme = strtolower($parts['scheme']);
        if (! in_array($scheme, ['http', 'https'], true)) {
            return ['valid' => false, 'error' => "Disallowed protocol [{$scheme}]. Only HTTP and HTTPS are permitted."];
        }

        $isProduction = app()->environment('production');
        if (($enforceHttps || $isProduction) && $scheme !== 'https') {
            $allowHttpDev = config('app.allow_http_integrations', false) || env('ALLOW_HTTP_INTEGRATIONS', false);
            if (! $allowHttpDev) {
                return ['valid' => false, 'error' => 'Production integration endpoints must use HTTPS.'];
            }
        }

        $host = strtolower($parts['host']);

        // 1. Check Cloud Metadata Endpoints (Critical SSRF)
        if (in_array($host, self::CLOUD_METADATA_HOSTS, true)) {
            return ['valid' => false, 'error' => 'Access to cloud metadata endpoints is strictly forbidden.'];
        }

        // 2. Validate IP addresses / hostnames in production environments
        if ($isProduction && ! config('app.allow_local_integrations', false)) {
            if ($host === 'localhost' || str_ends_with($host, '.localhost') || str_ends_with($host, '.internal') || str_ends_with($host, '.local')) {
                return ['valid' => false, 'error' => 'Localhost and internal domain endpoints are forbidden in production.'];
            }

            if (filter_var($host, FILTER_VALIDATE_IP)) {
                if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
                    return ['valid' => false, 'error' => 'Private and reserved IP addresses are forbidden for production integrations.'];
                }
            }
        }

        return ['valid' => true, 'error' => null];
    }
}
