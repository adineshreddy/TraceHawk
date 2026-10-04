-- Insertion clocks are diagnostic lower bounds, not transaction-commit clocks.
CREATE TABLE event_processing_receipts(receipt_id bigserial PRIMARY KEY,event_id text UNIQUE NOT NULL REFERENCES events ON DELETE CASCADE,run_id text NOT NULL REFERENCES runs ON DELETE CASCADE,inserted_at_us bigint NOT NULL);
CREATE INDEX receipt_run_cursor ON event_processing_receipts(run_id,receipt_id);
CREATE FUNCTION record_event_receipt() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO event_processing_receipts(event_id,run_id,inserted_at_us) VALUES(NEW.event_id,NEW.run_id,floor(extract(epoch FROM clock_timestamp())*1000000)::bigint);
  RETURN NEW;
END;
$$;
CREATE TRIGGER event_receipt AFTER INSERT ON events FOR EACH ROW EXECUTE FUNCTION record_event_receipt();
