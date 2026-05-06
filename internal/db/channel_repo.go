package db

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	sqlcgen "github.com/getlicense-io/getlicense-api/internal/db/sqlc/gen"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ChannelRepo implements domain.ChannelRepository against the sqlc-
// generated queries. Channels are account-scoped (env-agnostic), with
// a dual-branch RLS policy that lets both the vendor and the partner
// read a row.
type ChannelRepo struct {
	pool *pgxpool.Pool
	q    *sqlcgen.Queries
}

var _ domain.ChannelRepository = (*ChannelRepo)(nil)

// NewChannelRepo creates a new ChannelRepo.
func NewChannelRepo(pool *pgxpool.Pool) *ChannelRepo {
	return &ChannelRepo{pool: pool, q: sqlcgen.New()}
}

// channelJoinFields is the shared shape pulled from the per-query JOIN
// row types (GetChannelByIDRow, ListChannelsByVendorRow). They're
// structurally identical but nominally distinct, so each helper below
// copies onto this internal shape before running the shared translation.
type channelJoinFields struct {
	ID                pgtype.UUID
	VendorAccountID   pgtype.UUID
	PartnerAccountID  pgtype.UUID
	Name              string
	Description       *string
	Status            string
	DraftFirstProduct []byte
	CreatedAt         time.Time
	UpdatedAt         time.Time
	ClosedAt          *time.Time
	VendorName        string
	VendorSlug        string
	PartnerName       *string
	PartnerSlug       *string
}

func channelFromJoinFields(f channelJoinFields) domain.Channel {
	var draft json.RawMessage
	if f.DraftFirstProduct != nil {
		draft = json.RawMessage(f.DraftFirstProduct)
	}
	vendorID := idFromPgUUID[core.AccountID](f.VendorAccountID)
	c := domain.Channel{
		ID:                idFromPgUUID[core.ChannelID](f.ID),
		VendorAccountID:   vendorID,
		PartnerAccountID:  nullableIDFromPgUUID[core.AccountID](f.PartnerAccountID),
		Name:              f.Name,
		Description:       f.Description,
		Status:            domain.ChannelStatus(f.Status),
		DraftFirstProduct: draft,
		CreatedAt:         f.CreatedAt,
		UpdatedAt:         f.UpdatedAt,
		ClosedAt:          f.ClosedAt,
		VendorAccount: &domain.AccountSummary{
			ID:   vendorID,
			Name: f.VendorName,
			Slug: f.VendorSlug,
		},
	}
	if c.PartnerAccountID != nil && f.PartnerName != nil && f.PartnerSlug != nil {
		c.PartnerAccount = &domain.AccountSummary{
			ID:   *c.PartnerAccountID,
			Name: *f.PartnerName,
			Slug: *f.PartnerSlug,
		}
	}
	return c
}

// Get returns a single channel by id. Caller's RLS context must include
// the channel's vendor or partner account.
func (r *ChannelRepo) Get(ctx context.Context, id core.ChannelID) (*domain.Channel, error) {
	row, err := r.q.GetChannelByID(ctx, conn(ctx, r.pool), pgUUIDFromID(id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c := channelFromJoinFields(channelJoinFields{
		ID:                row.ID,
		VendorAccountID:   row.VendorAccountID,
		PartnerAccountID:  row.PartnerAccountID,
		Name:              row.Name,
		Description:       row.Description,
		Status:            row.Status,
		DraftFirstProduct: row.DraftFirstProduct,
		CreatedAt:         row.CreatedAt,
		UpdatedAt:         row.UpdatedAt,
		ClosedAt:          row.ClosedAt,
		VendorName:        row.VendorName,
		VendorSlug:        row.VendorSlug,
		PartnerName:       row.PartnerName,
		PartnerSlug:       row.PartnerSlug,
	})
	return &c, nil
}

// ListByVendor returns cursor-paginated channels owned by vendorAccountID.
func (r *ChannelRepo) ListByVendor(
	ctx context.Context,
	vendorAccountID core.AccountID,
	filter domain.ChannelListFilter,
	cursor core.Cursor,
	limit int,
) ([]domain.Channel, bool, error) {
	ts, id := cursorParams(cursor)
	var cursorID pgtype.UUID
	if id != nil {
		cursorID = pgtype.UUID{Bytes: *id, Valid: true}
	}
	var statusFilter *string
	if filter.Status != nil {
		s := string(*filter.Status)
		statusFilter = &s
	}
	var partnerFilter pgtype.UUID
	if filter.PartnerAccountID != nil {
		partnerFilter = pgUUIDFromID(*filter.PartnerAccountID)
	}
	rows, err := r.q.ListChannelsByVendor(ctx, conn(ctx, r.pool), sqlcgen.ListChannelsByVendorParams{
		VendorAccountID: pgUUIDFromID(vendorAccountID),
		StatusFilter:    statusFilter,
		PartnerFilter:   partnerFilter,
		CursorTs:        ts,
		CursorID:        cursorID,
		LimitPlusOne:    int32(limit + 1),
	})
	if err != nil {
		return nil, false, err
	}
	out := make([]domain.Channel, 0, len(rows))
	for _, row := range rows {
		out = append(out, channelFromJoinFields(channelJoinFields{
			ID:                row.ID,
			VendorAccountID:   row.VendorAccountID,
			PartnerAccountID:  row.PartnerAccountID,
			Name:              row.Name,
			Description:       row.Description,
			Status:            row.Status,
			DraftFirstProduct: row.DraftFirstProduct,
			CreatedAt:         row.CreatedAt,
			UpdatedAt:         row.UpdatedAt,
			ClosedAt:          row.ClosedAt,
			VendorName:        row.VendorName,
			VendorSlug:        row.VendorSlug,
			PartnerName:       row.PartnerName,
			PartnerSlug:       row.PartnerSlug,
		}))
	}
	out, hasMore := sliceHasMore(out, limit)
	return out, hasMore, nil
}

// --- P1 + P2 stubs (real implementations land in later tasks) ---

func (r *ChannelRepo) ListByPartner(
	ctx context.Context, partnerAccountID core.AccountID,
	filter domain.ChannelListFilter, cursor core.Cursor, limit int,
) ([]domain.Channel, bool, error) {
	ts, id := cursorParams(cursor)
	var cursorID pgtype.UUID
	if id != nil {
		cursorID = pgtype.UUID{Bytes: *id, Valid: true}
	}
	var statusFilter *string
	if filter.Status != nil {
		s := string(*filter.Status)
		statusFilter = &s
	}
	rows, err := r.q.ListChannelsByPartner(ctx, conn(ctx, r.pool), sqlcgen.ListChannelsByPartnerParams{
		PartnerAccountID: pgUUIDFromID(partnerAccountID),
		StatusFilter:     statusFilter,
		CursorTs:         ts,
		CursorID:         cursorID,
		LimitPlusOne:     int32(limit + 1),
	})
	if err != nil {
		return nil, false, err
	}
	out := make([]domain.Channel, 0, len(rows))
	for _, row := range rows {
		out = append(out, channelFromJoinFields(channelJoinFields{
			ID:                row.ID,
			VendorAccountID:   row.VendorAccountID,
			PartnerAccountID:  row.PartnerAccountID,
			Name:              row.Name,
			Description:       row.Description,
			Status:            row.Status,
			DraftFirstProduct: row.DraftFirstProduct,
			CreatedAt:         row.CreatedAt,
			UpdatedAt:         row.UpdatedAt,
			ClosedAt:          row.ClosedAt,
			VendorName:        row.VendorName,
			VendorSlug:        row.VendorSlug,
			PartnerName:       row.PartnerName,
			PartnerSlug:       row.PartnerSlug,
		}))
	}
	out, hasMore := sliceHasMore(out, limit)
	return out, hasMore, nil
}

func (r *ChannelRepo) ListProducts(
	ctx context.Context, channelID core.ChannelID,
	cursor core.Cursor, limit int,
) ([]domain.ChannelProduct, bool, error) {
	ts, id := cursorParams(cursor)
	var cursorID pgtype.UUID
	if id != nil {
		cursorID = pgtype.UUID{Bytes: *id, Valid: true}
	}
	rows, err := r.q.ListChannelProducts(ctx, conn(ctx, r.pool), sqlcgen.ListChannelProductsParams{
		ChannelID:    pgUUIDFromID(channelID),
		CursorTs:     ts,
		CursorID:     cursorID,
		LimitPlusOne: int32(limit + 1),
	})
	if err != nil {
		return nil, false, err
	}
	out := make([]domain.ChannelProduct, 0, len(rows))
	for _, row := range rows {
		caps := make([]domain.GrantCapability, len(row.Capabilities))
		for i, c := range row.Capabilities {
			caps[i] = domain.GrantCapability(c)
		}
		var constraints json.RawMessage
		if row.Constraints != nil {
			constraints = json.RawMessage(row.Constraints)
		}
		productID := idFromPgUUID[core.ProductID](row.ProductID)
		cp := domain.ChannelProduct{
			ID:           idFromPgUUID[core.GrantID](row.ID),
			ChannelID:    idFromPgUUID[core.ChannelID](row.ChannelID),
			ProductID:    productID,
			Status:       domain.ProjectGrantStatusToChannelProductStatus(domain.GrantStatus(row.Status)),
			Capabilities: caps,
			Constraints:  constraints,
			Product: &domain.ProductSummary{
				ID:   productID,
				Name: row.ProductName,
				Slug: row.ProductSlug,
			},
			CreatedAt: row.CreatedAt,
			UpdatedAt: row.UpdatedAt,
		}
		out = append(out, cp)
	}
	out, hasMore := sliceHasMore(out, limit)
	return out, hasMore, nil
}

func (r *ChannelRepo) GetStats(
	ctx context.Context, channelID core.ChannelID,
	callerAccountID core.AccountID, isPartner bool, since time.Time,
) (*domain.ChannelStats, error) {
	products, err := r.q.CountChannelProducts(ctx, conn(ctx, r.pool), pgUUIDFromID(channelID))
	if err != nil {
		return nil, err
	}
	licenses, err := r.q.CountChannelLicenses(ctx, conn(ctx, r.pool), sqlcgen.CountChannelLicensesParams{
		ChannelID:       pgUUIDFromID(channelID),
		SinceMonth:      since,
		IsPartner:       isPartner,
		CallerAccountID: pgUUIDFromID(callerAccountID),
	})
	if err != nil {
		return nil, err
	}
	customers, err := r.q.CountChannelCustomers(ctx, conn(ctx, r.pool), sqlcgen.CountChannelCustomersParams{
		ChannelID:       pgUUIDFromID(channelID),
		IsPartner:       isPartner,
		CallerAccountID: pgUUIDFromID(callerAccountID),
	})
	if err != nil {
		return nil, err
	}
	return &domain.ChannelStats{
		ProductsTotal:     products.Total,
		ProductsActive:    products.Active,
		LicensesTotal:     licenses.Total,
		LicensesThisMonth: licenses.ThisMonth,
		CustomersTotal:    customers,
	}, nil
}

// Create inserts a new channel row. Must be called inside a
// WithTargetAccount context scoped to the vendor account so RLS allows
// the INSERT. A unique violation on channels_unique_name (partial unique
// on (vendor_account_id, partner_account_id, lower(name)) WHERE status !=
// 'closed') is returned as-is — callers should use uniqueChannelName to
// avoid conflicts proactively.
func (r *ChannelRepo) Create(ctx context.Context, c *domain.Channel) error {
	return r.q.CreateChannel(ctx, conn(ctx, r.pool), sqlcgen.CreateChannelParams{
		ID:                pgUUIDFromID(c.ID),
		VendorAccountID:   pgUUIDFromID(c.VendorAccountID),
		PartnerAccountID:  pgUUIDFromIDPtr(c.PartnerAccountID),
		Name:              c.Name,
		Description:       c.Description,
		Status:            string(c.Status),
		DraftFirstProduct: nil,
		CreatedAt:         c.CreatedAt,
		UpdatedAt:         c.UpdatedAt,
	})
}

func (r *ChannelRepo) Update(ctx context.Context, id core.ChannelID, params domain.UpdateChannelParams) error {
	return errors.New("ChannelRepo.Update: not implemented in P0")
}

func (r *ChannelRepo) UpdateStatus(ctx context.Context, id core.ChannelID, status domain.ChannelStatus, closedAt *time.Time) error {
	return errors.New("ChannelRepo.UpdateStatus: not implemented in P0")
}

func (r *ChannelRepo) SetPartnerAndActivate(ctx context.Context, id core.ChannelID, partnerAccountID core.AccountID) error {
	return errors.New("ChannelRepo.SetPartnerAndActivate: not implemented in P0")
}

func (r *ChannelRepo) ClearDraftFirstProduct(ctx context.Context, id core.ChannelID) error {
	return errors.New("ChannelRepo.ClearDraftFirstProduct: not implemented in P0")
}
