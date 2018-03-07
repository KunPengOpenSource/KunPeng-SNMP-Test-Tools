// This file is part of SNMP#NET.
// 
// SNMP#NET is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// SNMP#NET is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with SNMP#NET.  If not, see <http://www.gnu.org/licenses/>.
// 
/* Changes:
 * Nov 21, 2008
 *  FxCop fix: replaced inherted class from List<Vb> to Collection<Vb>
 */
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Text;

namespace SnmpSharpNet {
	/// <summary>
	/// Variable Binding collection
	/// </summary>
	public class VbCollection : AsnType, IEnumerable<Vb> {
		List<Vb> _vbs;
		/// <summary>
		/// Standard constructor
		/// </summary>
		public VbCollection(): base() {
			// this is the SMI type for the VarBind sequence
			Type = SnmpConstants.SMI_SEQUENCE;
			// list to store VarBind
			_vbs = new List<Vb>();
		}
		/// <summary>
		/// Get number of VarBind entries in the collection
		/// </summary>
		public int Count
		{
			get
			{
				return _vbs.Count;
			}
		}
		/// <summary>
		/// Reset the VarBind collection.
		/// </summary>
		public void Clear()
		{
			_vbs.Clear();
		}
		/// <summary>
		/// Indexed access to VarBind collection.
		/// </summary>
		/// <param name="index">Index position of the VarBind entry</param>
		/// <returns>VarBind entry at the specified index</returns>
		/// <exception cref="IndexOutOfRangeException">Thrown when index is outside the bounds of the collection</exception>
		public Vb this[int index]
		{
			get
			{
				if (index < 0 && index >= _vbs.Count)
					throw new IndexOutOfRangeException("Requested VarBind entry is outside the collection range.");
				return _vbs[index];
			}
		}
		/// <summary>
		/// Remove VarBind entry for the specified position in the collection.
		/// </summary>
		/// <param name="pos">Position of the entry to remove (zero based)</param>
		/// <exception cref="IndexOutOfRangeException">Thrown when position is outside the bounds of the collection</exception>
		public void RemoveAt(int pos)
		{
			if (pos < 0 && pos >= _vbs.Count)
				throw new IndexOutOfRangeException("Requested VarBind entry is outside the collection range.");
			_vbs.RemoveAt(pos);
		}
		/// <summary>
		/// Insert VarBind item at specific location
		/// </summary>
		/// <param name="pos">Position (zero based)</param>
		/// <param name="item">VarBind item to insert</param>
		/// <exception cref="IndexOutOfRangeException">Thrown when position is outside the bounds of the collection</exception>
		public void Insert(int pos, Vb item)
		{
			if (pos < 0 && pos >= _vbs.Count)
				throw new IndexOutOfRangeException("Requested VarBind position is outside the collection range.");
			_vbs.Insert(pos, item);
		}
		/// <summary>
		/// Duplicate Vbs object
		/// </summary>
		/// <returns>Duplicate of the Vbs object</returns>
		public override Object Clone()
		{
			VbCollection vb = new VbCollection();
			foreach (Vb v in this)
			{
				vb.Add(v);
			}
			return vb;
		}
		/// <summary>
		/// Add variable binding to the collection
		/// </summary>
		/// <param name="vb">VarBind item to add to the collection</param>
		public void Add(Vb vb)
		{
			_vbs.Add(vb);
		}
		/// <summary>
		/// Add new VB to the collection. New Vb OID in string format is supplied. Value is set to null (as in request)
		/// </summary>
		/// <param name="oid">OID to set in the new Vb</param>
		public void Add(string oid)
		{
			Oid o = new Oid(oid);
			Vb v = new Vb(o);
			Add(v);
		}
		/// <summary>
		/// Add Vb with the supplied OID and value of SnmpNull
		/// </summary>
		/// <param name="oid">OID to assign to the new Vb</param>
		public void Add(Oid oid)
		{
			if (oid == null)
				throw new ArgumentNullException("oid", "Can't create vb entry with null Oid.");
			Vb v = new Vb(oid);
			Add(v);
		}
		/// <summary>
		/// Add Vb with the supplied OID and value of SnmpNull
		/// </summary>
		/// <param name="oid">OID to assign to the new Vb</param>
		/// <param name="value">SNMP value to assign to the new Vb</param>
		public void Add(Oid oid, AsnType value)
		{
			Vb v = new Vb(oid, value);
			Add(v);
		}

		/// <summary>
		/// Add content of the VbCollection to the end of the collection.
		/// </summary>
		/// <param name="varList">Variable Binding collection</param>
		public void Add(VbCollection varList)
		{
			if (varList != null)
			{
				foreach (Vb v in varList)
				{
					Add(v);
				}
			}
		}

		/// <summary>
		/// Get enumerator.
		/// </summary>
		/// <returns>Enumerator</returns>
		public IEnumerator<Vb> GetEnumerator()
		{
			return _vbs.GetEnumerator();
		}

		/// <summary>
		/// Get enumerator.
		/// </summary>
		/// <returns>Enumerator</returns>
		System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
		{
			return _vbs.GetEnumerator();
		}

		/// <summary>
		/// Encode VarBind collection sequence
		/// </summary>
		/// <param name="buffer">Target buffer. Encoded VarBind collection is appended.</param>
		public override void encode(MutableByte buffer)
		{
			MutableByte tmp = new MutableByte();
			foreach (Vb v in _vbs)
			{
				v.encode(tmp);
			}
			BuildHeader(buffer, Type, tmp.Length);
			buffer.Append(tmp);
		}

		/// <summary>
		/// Decode VarBind collection sequence.
		/// </summary>
		/// <param name="buffer">Buffer containing BER encoded VarBind collection</param>
		/// <param name="offset">Offset to start decoding from</param>
		/// <returns>New offset of the position following the VarBind collection</returns>
		/// <exception cref="SnmpException">Thrown when parsed ASN.1 type is not a VarBind collection sequence type</exception>
		public override int decode(byte[] buffer, int offset)
		{
			int headerLen;
			byte b = ParseHeader(buffer, ref offset, out headerLen);
			if( b != Type )
				throw new SnmpException("Invalid ASN.1 encoding for variable binding list.");

			_vbs.Clear();

			int oldOffset = offset;
			while (headerLen > 0)
			{
				Vb vb = new Vb();
				offset = vb.decode(buffer, offset);

				headerLen -= (offset - oldOffset);
				oldOffset = offset;
				_vbs.Add(vb);
			}
			return offset;
		}
	}
}
