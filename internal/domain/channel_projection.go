package domain

// ProjectGrantStatusToChannelProductStatus maps a grant.status value to
// its ChannelProduct.status wire-level name. Mapping:
//
//	grant.active                      → channel-product.active
//	grant.suspended                   → channel-product.paused
//	grant.revoked / left / expired    → channel-product.closed
//	grant.pending                     → channel-product.active
//	                                    (defensive default — pending grants
//	                                    are never directly observable as
//	                                    channel-products because activation
//	                                    flips the parent channel atomically.)
func ProjectGrantStatusToChannelProductStatus(s GrantStatus) ChannelProductStatus {
	switch s {
	case GrantStatusSuspended:
		return ChannelProductStatusPaused
	case GrantStatusRevoked, GrantStatusLeft, GrantStatusExpired:
		return ChannelProductStatusClosed
	default:
		return ChannelProductStatusActive
	}
}
